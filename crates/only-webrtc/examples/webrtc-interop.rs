//! Interop peer for `tools/interop/webrtc/run.sh` (against pion).
//!
//! ```text
//! webrtc-interop server <udp-addr> <http-addr>         ICE-lite RtcServer: data channel and media
//!                                                      echo; offers are POSTed to http://<http-addr>/
//! webrtc-interop client <http-addr> dc|media           an Endpoint (full ICE) offering to a server
//! webrtc-interop client <http-addr> dc-relay <turn> <user> <password>
//!                                                      the same offering relayed candidates only
//!                                                      (an allocation on the TURN server at <turn>)
//! webrtc-interop server <udp-addr> <http-addr> <tcp-addr>
//!                                                      the same, also with a passive ICE-TCP
//!                                                      candidate on <tcp-addr>
//! webrtc-interop sfu <udp-addr> <http-addr> [<proxy-addr> loss-out=<%> [periodic]]
//!                                                      ICE-lite simulcast forwarding: POST /publish
//!                                                      a simulcast offer; POST /view gets an
//!                                                      offer (a simulcast line relaying every
//!                                                      layer, a plain line with the selected
//!                                                      layer, a "ctl" channel taking "layer
//!                                                      <rid>"), POST /view-answer its answer;
//!                                                      behind a lossy proxy (as fec-server's)
//!                                                      when <proxy-addr> is given
//! webrtc-interop client <http-addr> dc-tcp             the same offering its passive ICE-TCP
//!                                                      candidate only
//! webrtc-interop client <http-addr> dc-active          the same offering its active ICE-TCP
//!                                                      candidate only
//! webrtc-interop client <http-addr> dc-mdns            the same on the primary address, which the
//!                                                      offer conceals behind an mDNS name; the
//!                                                      answer's mDNS names are resolved (each
//!                                                      resolution logged with ONLY_LOG=debug)
//! webrtc-interop client <http-addr> dc-relay-url <turn:|turns: URL> <user> <password>
//!                                                      relayed candidates only, allocated over
//!                                                      UDP, TCP or TLS
//! webrtc-interop client <http-addr> simulcast          offers VP8 simulcast h/m/l and a "stats"
//!                                                      channel; checks the answerer got all three
//! webrtc-interop turn <udp-addr> <relay-ip> <user> <password> [<tcp-addr> [<tls-addr> [<dtls-addr>]]]
//!                                                      a TURN server (realm "only"), also on TCP,
//!                                                      TLS and DTLS (self-signed) when given
//! webrtc-interop turn-client udp|tcp|tls|dtls <server> <user> <password> [<relay-port-check>]
//!                                                      the only_turn client: allocate, then 20
//!                                                      datagrams through a channel to a local
//!                                                      echo peer and back
//! webrtc-interop relay-echo <turn:|turns: URL> <user> <password>
//!                                                      two Endpoints with relayed candidates only
//!                                                      from that server (UDP, TCP, TLS or DTLS),
//!                                                      a data channel echo between them
//! webrtc-interop mdns-conceal <udp-addr> <secs>        an Endpoint on <udp-addr> concealing its
//!                                                      host candidate: prints "name <uuid>.local"
//!                                                      and answers mDNS queries for <secs> s
//! webrtc-interop mdns-resolve <addr-a> <addr-b> <name> two Endpoints: B (on <addr-b>) offers its
//!                                                      host candidate as <name>, which another
//!                                                      responder publishes; A (on <addr-a>)
//!                                                      resolves it over mDNS and connects (B gets
//!                                                      no candidates, so only A's resolution can
//!                                                      connect them), 20 data channel echoes
//! ```
//! webrtc-interop fec-server <udp-addr> <proxy-addr> <http-addr> [fec=ulpfec|flexfec]
//!     [min=<n>] [loss-out=<%>] [loss-in=<%>] [periodic] [ccfb] [xr] [tmmbr=<bps>] [bwe]
//!     [bwemax=<bps>] [nopace] [pli=<ms>] [direct]
//!                                                      the server with FEC (protection factor at
//!                                                      least <n>/256), RFC 8888, RTCP XR and
//!                                                      TMMBR (a request for <bps> after 3 s);
//!                                                      the answer's candidate is <proxy-addr>,
//!                                                      a UDP proxy to <udp-addr> that drops
//!                                                      that share of the RTP it forwards
//!                                                      (out: to the browser; at random, or
//!                                                      one in 100/<%> with periodic) and logs
//!                                                      the bursts of RTP to the browser
//!                                                      (packets less than 300 us apart); prints
//!                                                      the statistics every second; bwemax caps
//!                                                      the estimate, nopace turns pacing off,
//!                                                      pli asks for a keyframe every <ms>
//! webrtc-interop client <http-addr> media-in           offers audio (and a data channel), sends
//!                                                      Opus and waits for 100 audio frames from
//!                                                      the answerer
//! webrtc-interop client <http-addr> sip [<n>]          a SIP-style phone (ADR-077): SDES-SRTP
//!                                                      without ICE, audio only, its bound address
//!                                                      in c= / m=; sends Opus first and waits for
//!                                                      <n> (100) packets echoed
//! webrtc-interop sip-gateway <udp-addr> <http-addr>    a SIP-style gateway: an Endpoint on
//!                                                      <udp-addr> taking offers without ICE
//!                                                      (SDES-SRTP), latching as ONLY_INTEROP_LATCH
//!                                                      says, echoing media
//! Signalling is one HTTP POST: the offer as the body, the answer as the response body.
//!
//! Every mode takes these from the environment (ADR-048): ONLY_INTEROP_DTLS13=0|1 (DTLS 1.2
//! only, or the default DTLS 1.3 with 1.2 fallback), ONLY_INTEROP_CRYPTEX=1, ONLY_INTEROP_RED=<0..2> (Opus RED),
//! ONLY_INTEROP_FEC=ulpfec|flexfec with ONLY_INTEROP_FEC_MIN=<n>, ONLY_INTEROP_STATS=1
//! (statistics events every second, printed), ONLY_INTEROP_ECN=ect0|ect1 (ECN-capable RTP,
//! ADR-077), ONLY_INTEROP_LATCH=once|rebind (latching media without ICE; rebind: after 1 s
//! of silence), ONLY_INTEROP_SIP=1 (SDES-SRTP without ICE), ONLY_INTEROP_BWE=<bps> (the
//! bandwidth estimator, starting there). fec-server's `direct` option
//! serves <proxy-addr> itself, without the proxy (which would clear ECN marks). With ONLY_LOG=only_webrtc=debug the DTLS
//! version of each connection is logged.
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
    ChannelId, Codec, Direction, Endpoint, Event, FecMechanism, Frequency, KeyframeRequest,
    KeyframeRequestKind, MediaData, MediaKind, MediaTime, Mid, Peer, PeerHandler, RelayServer,
    RtcServer,
};

/// The ADR-048 switches from the environment (see the module documentation).
fn extras(mut c: only_webrtc::RtcConfig) -> only_webrtc::RtcConfig {
    let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    if let Some(v) = env("ONLY_INTEROP_DTLS13") {
        c = c.enable_dtls13(v != "0");
    }
    if env("ONLY_INTEROP_CRYPTEX").is_some() {
        c = c.enable_cryptex(true);
    }
    if let Some(n) = env("ONLY_INTEROP_RED").and_then(|v| v.parse().ok()) {
        c = c.enable_opus_red(Some(n));
    }
    match env("ONLY_INTEROP_FEC").as_deref() {
        Some("ulpfec") => c = c.enable_fec(Some(FecMechanism::Ulpfec)),
        Some("flexfec") => c = c.enable_fec(Some(FecMechanism::FlexFec)),
        _ => {}
    }
    if let Some(m) = env("ONLY_INTEROP_FEC_MIN").and_then(|v| v.parse::<u8>().ok()) {
        c = c.set_fec_protection(m, 128.max(m));
    }
    if env("ONLY_INTEROP_STATS").is_some() {
        c = c.set_stats_interval(Some(Duration::from_secs(1)));
    }
    if env("ONLY_INTEROP_BUNDLE").as_deref() == Some("off") {
        c = c.set_bundle_policy(only_webrtc::BundlePolicy::Disabled);
    }
    match env("ONLY_INTEROP_ECN").as_deref() {
        Some("ect0") => c = c.set_ecn_marking(only_webrtc::EcnMarking::Ect0),
        Some("ect1") => c = c.set_ecn_marking(only_webrtc::EcnMarking::Ect1),
        _ => {}
    }
    match env("ONLY_INTEROP_LATCH").as_deref() {
        Some("once") => c = c.set_latching(only_webrtc::Latching::Once),
        Some("rebind") => {
            c = c.set_latching(only_webrtc::Latching::Rebind(Duration::from_secs(1)));
        }
        _ => {}
    }
    if let Some(b) = env("ONLY_INTEROP_BWE").and_then(|v| v.parse::<u64>().ok()) {
        c = c.enable_bwe(Some(b));
    }
    if env("ONLY_INTEROP_SIP").is_some() {
        c = c.enable_sdes_srtp(true).enable_ice(false);
    }
    c
}

/// Echoes data channel messages and media samples; answers a keyframe request with a text
/// message on the first data channel.
struct Echo {
    first: Option<ChannelId>,
    media: u64,
}

impl PeerHandler for Echo {
    fn on_channel_open(&mut self, p: &Peer, id: ChannelId, label: &str) {
        let prio = p.channel_priority(id).ok();
        eprintln!("server: channel {label:?} open, priority {prio:?}");
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
    fn on_event(&mut self, _p: &Peer, e: &Event) {
        eprintln!("server: event {e:?}");
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

fn server(udp: SocketAddr, http: SocketAddr, tcp: Option<SocketAddr>) {
    let mut rtc = RtcServer::new(vec![udp]).config(|| extras(only_webrtc::rtc_config()));
    if let Some(t) = tcp {
        rtc = rtc.tcp_candidates(vec![t]);
    }
    let mut b = Engine::builder().listen(Listener::udp(udp).threads(1).serve(rtc.clone()));
    if let Some(t) = tcp {
        b = b.listen(Listener::tcp(t).threads(1).serve(rtc.tcp()));
    }
    let engine = b.build().expect("engine");
    engine.start().expect("start");
    let l = TcpListener::bind(http).expect("http bind");
    eprintln!("server: udp {udp}, tcp {tcp:?}, signalling http://{http}/");
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

/// A SIP-style gateway (ADR-077): an Endpoint taking offers without ICE over SDES-SRTP, which
/// echoes media and latches as `ONLY_INTEROP_LATCH` says.
fn sip_gateway(udp: SocketAddr, http: SocketAddr) {
    let engine = Engine::builder()
        .udp_client_threads(1)
        .build()
        .expect("engine");
    engine.start().expect("start");
    let ep = Endpoint::bind(&engine, udp).expect("bind").config(|| {
        extras(only_webrtc::rtc_config())
            .enable_sdes_srtp(true)
            .enable_ice(false)
            .set_stats_interval(Some(Duration::from_secs(1)))
    });
    let l = TcpListener::bind(http).expect("http bind");
    eprintln!("gateway: udp {udp}, signalling http://{http}/");
    for s in l.incoming() {
        let Ok(mut s) = s else { continue };
        let (_, offer) = read_http(&mut s);
        let h = Echo {
            first: None,
            media: 0,
        };
        respond(
            &mut s,
            ep.accept_offer(&offer, h)
                .map(|(_, a)| a)
                .map_err(|e| e.to_string()),
        );
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
    fn on_event(&mut self, _p: &Peer, e: &Event) {
        eprintln!("client: event {e:?}");
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
    // ONLY_INTEROP_BIND: another local address (Firefox pairs no loopback candidates).
    // mDNS: the address browsers conceal theirs behind (the LAN, not loopback).
    let bind = std::env::var("ONLY_INTEROP_BIND").unwrap_or_else(|_| {
        if what == "dc-mdns" {
            "0.0.0.0:0"
        } else {
            "127.0.0.1:0"
        }
        .into()
    });
    let ep = Endpoint::bind(&engine, bind.parse().expect("addr")).expect("bind");
    // ONLY_INTEROP_NOMINATION=aggressive|renomination: how this (controlling) side nominates.
    let nomination = std::env::var("ONLY_INTEROP_NOMINATION").unwrap_or_default();
    let ep = ep.config(move || {
        extras(only_webrtc::rtc_config())
            .enable_ice_aggressive_nomination(nomination == "aggressive")
            .enable_ice_renomination(nomination == "renomination")
    });
    // Force the transport, as a browser's iceTransportPolicy: only the candidates offered.
    let ep = match what {
        "dc-relay" | "dc-relay-url" => ep.candidate_filter(|c| c.kind() == "relay"),
        "dc-tcp" => ep.candidate_filter(|c| c.to_sdp().contains("tcptype passive")),
        "dc-active" => ep.candidate_filter(|c| c.to_sdp().contains("tcptype active")),
        _ => ep,
    };
    if what == "dc-relay" {
        let turn: SocketAddr = args[0].parse().expect("turn addr");
        let r = ep
            .gather_relay(turn, &args[1], &args[2], Duration::from_secs(10))
            .expect("allocate");
        eprintln!("client: relayed candidate {r}");
    }
    if what == "dc-relay-url" {
        // A turn:/turns: URL; TLS without verification (the interop servers' certificates
        // are self-signed).
        let mut s = RelayServer::from_url(&args[0], &args[1], &args[2]).expect("url");
        if matches!(s.transport(), "tls" | "dtls") {
            s = s.tls_config(
                tls::ClientConfig::builder()
                    .insecure_skip_verify()
                    .build()
                    .expect("tls config"),
            );
        }
        let r = ep
            .gather_relay_via(&engine, &s, Duration::from_secs(10))
            .expect("allocate");
        eprintln!("client: relayed candidate {r} over {}", s.transport());
    }
    if what == "dc-mdns" {
        ep.resolve_mdns(&engine, Duration::from_secs(5))
            .expect("mdns");
        ep.conceal_host_candidates().expect("conceal");
    }
    if what == "dc-active" {
        let a = ep.dial_tcp(&engine).expect("active tcp");
        eprintln!("client: active ICE-TCP candidate {a}");
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
            // ONLY_INTEROP_PRIORITY=high: the channel's DCEP priority.
            let prio = match std::env::var("ONLY_INTEROP_PRIORITY").as_deref() {
                Ok("high") => only_webrtc::ChannelPriority::High,
                Ok("medium") => only_webrtc::ChannelPriority::Medium,
                Ok("very-low") => only_webrtc::ChannelPriority::VeryLow,
                _ => only_webrtc::ChannelPriority::Low,
            };
            let label = if what == "simulcast" {
                "stats"
            } else {
                "interop"
            };
            if what != "sip" {
                api.add_channel_with_config(
                    &only_webrtc::ChannelConfig::new(label).with_priority(prio),
                );
            }
            if what == "media" || what == "media-in" || what == "sip" {
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
        "dc-relay" | "dc-relay-url" => filter_candidates(&offer, |l| l.contains(" typ relay")),
        "dc-tcp" => filter_candidates(&offer, |l| l.contains("tcptype passive")),
        "dc-active" => filter_candidates(&offer, |l| l.contains("tcptype active")),
        "dc-mdns" => filter_candidates(&offer, |l| l.contains(" udp ")),
        _ => offer,
    };
    if what == "dc-mdns" {
        assert!(
            offer
                .lines()
                .any(|l| l.contains(".local ") && l.contains(" typ host")),
            "no concealed host candidate:\n{offer}"
        );
    }
    let answer = post(http, &offer);
    if what == "dc-mdns" {
        let n = answer
            .lines()
            .filter(|l| l.starts_with("a=candidate") && l.contains(".local "))
            .count();
        eprintln!("client: the answer has {n} mDNS candidates");
        assert!(
            n > 0,
            "Chrome did not conceal its host candidates:\n{answer}"
        );
    }
    peer.accept_answer(&answer).expect("answer");
    let deadline = Instant::now() + Duration::from_secs(15);
    let next = || {
        rx.recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .expect("timed out")
    };
    if what == "sip" {
        // The phone speaks first: the gateway knows only the address in our description.
        let mid = audio.expect("audio");
        let pt = peer.payload_type(mid, Codec::Opus).expect("opus");
        let want: usize = args.first().and_then(|v| v.parse().ok()).unwrap_or(100);
        let deadline = Instant::now() + Duration::from_secs(5 + want as u64 / 25);
        let (mut n, mut i) = (0, 0u64);
        while n < want {
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
            assert!(Instant::now() < deadline, "no echo ({n} back of {i})");
        }
        println!("ok: {n} Opus packets echoed back to the phone (sent {i})");
        peer.close();
        return;
    }
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
        if what == "dc-mdns" {
            // Chrome's checks may have connected us before its name resolved: let the
            // queries finish, for the log browser.sh checks.
            std::thread::sleep(Duration::from_secs(1));
        }
    } else if what == "media" {
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
    if what == "media-in" {
        // The answerer's own audio (and ours to it).
        let mid = audio.expect("audio");
        let pt = peer.payload_type(mid, Codec::Opus).expect("opus");
        let (mut n, mut i) = (0, 0u64);
        let deadline = Instant::now() + Duration::from_secs(20);
        while n < 100 {
            // 20 ms of Opus silence (a CELT frame Chrome decodes).
            let t = MediaTime::new(i * 960, Frequency::FORTY_EIGHT_KHZ);
            peer.write_media(mid, pt, Instant::now(), t, &[0xf8, 0xff, 0xfe])
                .expect("write");
            i += 1;
            std::thread::sleep(Duration::from_millis(20));
            while let Ok(g) = rx.try_recv() {
                if matches!(g, Got::Media(_)) {
                    n += 1;
                }
            }
            assert!(
                Instant::now() < deadline,
                "no audio from the answerer ({n})"
            );
        }
        // Chrome counts what we sent too: keep sending a while.
        for _ in 0..150 {
            let t = MediaTime::new(i * 960, Frequency::FORTY_EIGHT_KHZ);
            peer.write_media(mid, pt, Instant::now(), t, &[0xf8, 0xff, 0xfe])
                .expect("write");
            i += 1;
            std::thread::sleep(Duration::from_millis(20));
        }
        println!("ok: {n} audio frames from the answerer (sent {i})");
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
    let ck = only_x509::generate_simple_self_signed(["localhost"]).expect("cert");
    let scfg = tls::ServerConfig::builder(
        vec![tls::Certificate::from_der(ck.0.as_der().to_vec())],
        tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der()),
    )
    .build()
    .expect("tls config");
    if let Some(tl) = streams.get(1) {
        b = b.listen(
            Listener::tcp(tl.parse().expect("tls addr"))
                .threads(1)
                .serve(tls::Tls::server(scfg.clone(), turn.stream())),
        );
    }
    if let Some(d) = streams.get(2) {
        b = b.listen(
            Listener::udp(d.parse().expect("dtls addr"))
                .threads(1)
                .serve(turn.dtls(&scfg).expect("dtls")),
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
    /// A DTLS client connection (connected) on a UDP socket, and the records it decrypted.
    Dtls(
        std::net::UdpSocket,
        Box<only_dtls::Connection>,
        std::collections::VecDeque<Vec<u8>>,
    ),
}

impl Wire {
    /// A DTLS handshake with `addr` (DTLS 1.3 offered, 1.2 accepted; no verification: the
    /// interop servers' certificates are self-signed).
    fn dtls(s: std::net::UdpSocket, addr: SocketAddr) -> Wire {
        s.connect(addr).expect("connect");
        let cfg = only_dtls::Config::without_identity()
            .with_versions(vec![only_dtls::Version::Dtls13, only_dtls::Version::Dtls12]);
        let mut c =
            only_dtls::Connection::client(Arc::new(cfg), Instant::now()).expect("dtls client");
        let end = Instant::now() + Duration::from_secs(10);
        let mut buf = [0u8; 4096];
        while !c.is_connected() {
            assert!(Instant::now() < end, "dtls handshake timed out");
            while let Some(d) = c.poll_transmit() {
                s.send(&d).expect("send");
            }
            match s.recv(&mut buf) {
                Ok(n) => c.handle_datagram(Instant::now(), &buf[..n]).expect("dtls"),
                Err(_) => c.handle_timeout(Instant::now()).expect("dtls"),
            }
        }
        while let Some(d) = c.poll_transmit() {
            s.send(&d).expect("send");
        }
        eprintln!("turn-client: DTLS connected ({})", c.version());
        Wire::Dtls(s, Box::new(c), std::collections::VecDeque::new())
    }

    fn send(&mut self, m: &[u8]) {
        match self {
            Wire::Udp(s, to) => {
                s.send_to(m, *to).expect("send");
            }
            Wire::Dtls(s, c, _) => {
                c.send_application_data(m).expect("dtls send");
                while let Some(d) = c.poll_transmit() {
                    s.send(&d).expect("send");
                }
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
        if let Wire::Dtls(s, c, q) = self {
            if q.is_empty() {
                let mut d = vec![0u8; 65536];
                match s.recv(&mut d) {
                    Ok(n) => c.handle_datagram(Instant::now(), &d[..n]).expect("dtls"),
                    Err(_) => c.handle_timeout(Instant::now()).expect("dtls"),
                }
                while let Some(e) = c.poll_event() {
                    if let only_dtls::Event::ApplicationData(m) = e {
                        q.push_back(m);
                    }
                }
                while let Some(d) = c.poll_transmit() {
                    s.send(&d).expect("send");
                }
            }
            let m = q.pop_front()?;
            buf[..m.len()].copy_from_slice(&m);
            return Some(m.len());
        }
        let r = match self {
            Wire::Udp(s, _) => s.recv(buf),
            Wire::Tcp(s) => s.read(buf),
            Wire::Tls(s) => s.read(buf),
            Wire::Dtls(..) => unreachable!(),
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
        "dtls" => {
            let s = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
            s.set_read_timeout(short).expect("timeout");
            Wire::dtls(s, addr)
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
    let stream = matches!(transport, "tcp" | "tls");
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

/// Two Endpoints with relayed candidates only, allocated on the TURN server of `url`, and a
/// data channel echo between them.
fn relay_echo(url: &str, user: &str, pass: &str) {
    let engine = Arc::new(
        Engine::builder()
            .udp_client_threads(1)
            .client_threads(1)
            .build()
            .expect("engine"),
    );
    engine.start().expect("start");
    let mut s = RelayServer::from_url(url, user, pass).expect("url");
    if matches!(s.transport(), "tls" | "dtls") {
        s = s.tls_config(
            tls::ClientConfig::builder()
                .insecure_skip_verify()
                .build()
                .expect("tls config"),
        );
    }
    let ep = || {
        let e = Endpoint::bind(&engine, "127.0.0.1:0".parse().expect("addr"))
            .expect("bind")
            .candidate_filter(|c| c.kind() == "relay");
        let r = e
            .gather_relay_via(&engine, &s, Duration::from_secs(10))
            .expect("allocate");
        eprintln!("relay-echo: relayed candidate {r} over {}", s.transport());
        e
    };
    let (a, b) = (ep(), ep());
    let (tx, rx) = channel();
    let mut ch = None;
    let (pa, offer) = a
        .create_offer(Collect(Mutex::new(tx)), |api| {
            ch = Some(api.add_channel("echo"));
        })
        .expect("offer");
    assert!(
        offer.contains(" typ relay") && !offer.contains(" typ host"),
        "{offer}"
    );
    let (_pb, answer) = b.accept_offer(&offer, EchoBack).expect("answer");
    pa.accept_answer(&answer).expect("accept");
    let ch = ch.expect("channel");
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut open = false;
    let mut back = 0;
    while back < 20 {
        assert!(
            Instant::now() < deadline,
            "relay-echo: timed out ({back} back)"
        );
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(None) => {
                open = true;
                pa.send(ch, b"through the relays 0", true).expect("send");
            }
            Ok(Some(d)) => {
                assert_eq!(d, format!("through the relays {back}").as_bytes());
                back += 1;
                if back < 20 {
                    let m = format!("through the relays {back}");
                    pa.send(ch, m.as_bytes(), true).expect("send");
                }
            }
            Err(_) => {}
        }
    }
    assert!(open);
    println!(
        "ok: Endpoints relayed through {url} ({}): data channel, 20 echoes",
        s.transport()
    );
    a.close();
    b.close();
}

/// An engine with one UDP and one TCP I/O thread, started.
fn small_engine() -> Arc<Engine> {
    let engine = Arc::new(
        Engine::builder()
            .udp_client_threads(1)
            .client_threads(1)
            .build()
            .expect("engine"),
    );
    engine.start().expect("start");
    engine
}

fn mdns_conceal(bind: SocketAddr, secs: u64) {
    let engine = small_engine();
    let ep = Endpoint::bind(&engine, bind).expect("bind");
    ep.resolve_mdns(&engine, Duration::from_secs(5))
        .expect("mdns");
    ep.conceal_host_candidates().expect("conceal");
    let (peer, offer) = ep
        .create_offer(EchoBack, |api| {
            api.add_channel("x");
        })
        .expect("offer");
    let name = offer
        .lines()
        .filter(|l| l.starts_with("a=candidate") && l.contains(" typ host"))
        .find_map(|l| {
            l.split_whitespace()
                .nth(4)
                .filter(|a| a.ends_with(".local"))
        })
        .expect("a concealed host candidate")
        .to_owned();
    println!("name {name}");
    let _ = std::io::stdout().flush();
    std::thread::sleep(Duration::from_secs(secs));
    peer.close();
    ep.close();
}

fn mdns_resolve(a_bind: SocketAddr, b_bind: SocketAddr, name: &str) {
    let engine = small_engine();
    let a = Endpoint::bind(&engine, a_bind).expect("bind a");
    a.resolve_mdns(&engine, Duration::from_secs(10))
        .expect("mdns");
    let b = Endpoint::bind(&engine, b_bind).expect("bind b");
    let (tx, rx) = channel();
    let mut ch = None;
    let (pb, offer) = b
        .create_offer(Collect(Mutex::new(tx)), |api| {
            ch = Some(api.add_channel("echo"));
        })
        .expect("offer");
    // B's host candidate as `name`; its other candidates dropped.
    let ip = b_bind.ip().to_string();
    let offer: String = offer
        .lines()
        .filter_map(|l| {
            if !l.starts_with("a=candidate") {
                return Some(format!("{l}\r\n"));
            }
            let mut f: Vec<&str> = l.split(' ').collect();
            (f.len() > 7 && f[2] == "udp" && f[4] == ip && f[7] == "host").then(|| {
                f[4] = name;
                format!("{}\r\n", f.join(" "))
            })
        })
        .collect();
    assert!(offer.contains(name), "{offer}");
    let (_pa, answer) = a.accept_offer(&offer, EchoBack).expect("answer");
    // B gets none of A's candidates: A's checks (to the resolved address) connect them.
    pb.accept_answer(&filter_candidates(&answer, |_| false))
        .expect("accept");
    let ch = ch.expect("channel");
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut back = 0;
    while back < 20 {
        assert!(
            Instant::now() < deadline,
            "mdns-resolve: timed out ({back} back)"
        );
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(None) => pb.send(ch, b"resolved 0", true).map(drop).expect("send"),
            Ok(Some(d)) => {
                assert_eq!(d, format!("resolved {back}").as_bytes());
                back += 1;
                if back < 20 {
                    let m = format!("resolved {back}");
                    pb.send(ch, m.as_bytes(), true).map(drop).expect("send");
                }
            }
            Err(_) => {}
        }
    }
    println!("ok: {name} resolved over mDNS, data channel, 20 echoes");
    a.close();
    b.close();
}

/// Sends `None` when the channel opens, then each message.
struct Collect(Mutex<Sender<Option<Vec<u8>>>>);
impl PeerHandler for Collect {
    fn on_channel_open(&mut self, _p: &Peer, _id: ChannelId, _label: &str) {
        let _ = self.0.lock().expect("lock").send(None);
    }
    fn on_channel_data(&mut self, _p: &Peer, _id: ChannelId, data: &[u8], _binary: bool) {
        let _ = self.0.lock().expect("lock").send(Some(data.to_vec()));
    }
}

/// Echoes data channel messages.
struct EchoBack;
impl PeerHandler for EchoBack {
    fn on_channel_data(&mut self, p: &Peer, id: ChannelId, data: &[u8], binary: bool) {
        let _ = p.send(id, data, binary);
    }
}

fn main() {
    let _ = only_log::init_from_env(only_log::LevelFilter::Warn);
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(String::as_str) {
        Some("server") => server(
            a[2].parse().expect("udp"),
            a[3].parse().expect("http"),
            a.get(4).map(|t| t.parse().expect("tcp")),
        ),
        Some("sfu") => sfu(
            a[2].parse().expect("udp"),
            a[3].parse().expect("http"),
            &a[4..],
        ),
        Some("fec-server") => fec_server(
            a[2].parse().expect("udp"),
            a[3].parse().expect("proxy"),
            a[4].parse().expect("http"),
            &a[5..],
        ),
        Some("client") => client(&a[2], &a[3], &a[4..]),
        Some("sip-gateway") => sip_gateway(a[2].parse().expect("udp"), a[3].parse().expect("http")),
        Some("turn") => turn(a[2].parse().expect("udp"), &a[3], &a[4], &a[5], &a[6..]),
        Some("turn-client") => turn_client(&a[2], &a[3], &a[4], &a[5]),
        Some("relay-echo") => relay_echo(&a[2], &a[3], &a[4]),
        Some("mdns-conceal") => {
            mdns_conceal(a[2].parse().expect("addr"), a[3].parse().expect("secs"));
        }
        Some("mdns-resolve") => mdns_resolve(
            a[2].parse().expect("addr a"),
            a[3].parse().expect("addr b"),
            &a[4],
        ),
        _ => eprintln!("usage: webrtc-interop server|client|turn|turn-client ..."),
    }
}

// ---- sfu: simulcast in from a browser, simulcast and a selected layer out ----

#[derive(Default)]
struct Sfu {
    publisher: Option<(Peer, Mid)>,
    viewers: Vec<Viewer>,
    /// Frames received per RID.
    counts: std::collections::BTreeMap<String, u64>,
}

struct Viewer {
    peer: Peer,
    /// The simulcast line (every layer, as received).
    sim: Mid,
    /// The plain line: the selected layer only.
    plain: Mid,
    /// The layer forwarded on `plain`, and the one asked for (switched at its next keyframe).
    current: Option<String>,
    wanted: String,
    /// RTP time rewriting of the plain line: output = input + offset.
    offset: u64,
    last_out: u64,
}

type SfuState = Arc<Mutex<Sfu>>;

struct Publisher(SfuState);

/// A VP8 key frame: the frame tag's P bit is 0.
fn vp8_key(frame: &[u8]) -> bool {
    frame.first().is_some_and(|b| b & 1 == 0)
}

impl PeerHandler for Publisher {
    fn on_media_added(&mut self, p: &Peer, m: &only_webrtc::MediaAdded) {
        if m.kind == MediaKind::Video {
            self.0.lock().expect("lock").publisher = Some((p.clone(), m.mid));
        }
    }
    fn on_media_data(&mut self, _p: &Peer, d: &MediaData) {
        let Some(rid) = d.rid.clone() else { return };
        let mut st = self.0.lock().expect("lock");
        *st.counts.entry(rid.clone()).or_default() += 1;
        let key = vp8_key(&d.data);
        for v in &mut st.viewers {
            if let Some(pt) = v.peer.payload_type(v.sim, Codec::Vp8) {
                let _ = v
                    .peer
                    .write_simulcast(v.sim, &rid, pt, Instant::now(), d.time, &d.data);
            }
            // Layer selection: switch at a key frame of the wanted layer.
            if v.current.as_deref() != Some(rid.as_str()) {
                if rid != v.wanted || !key {
                    continue;
                }
                let input = d.time.ticks();
                v.offset = v.last_out.wrapping_add(3000).wrapping_sub(input);
                eprintln!("sfu: viewer {} now gets layer {rid}", v.peer.id());
                v.current = Some(rid.clone());
            }
            let out = d.time.ticks().wrapping_add(v.offset) & 0xffff_ffff;
            v.last_out = out;
            if let Some(pt) = v.peer.payload_type(v.plain, Codec::Vp8) {
                let t = MediaTime::new(out, Frequency::NINETY_KHZ);
                let _ = v.peer.write_media(v.plain, pt, Instant::now(), t, &d.data);
            }
        }
    }
    fn on_close(&mut self, _p: &Peer) {
        eprintln!(
            "sfu: publisher closed: {:?}",
            self.0.lock().expect("lock").counts
        );
    }
}

struct ViewerHandler(SfuState);

impl PeerHandler for ViewerHandler {
    fn on_channel_data(&mut self, p: &Peer, id: ChannelId, data: &[u8], _binary: bool) {
        let msg = String::from_utf8_lossy(data).to_string();
        let mut st = self.0.lock().expect("lock");
        if let Some(rid) = msg.strip_prefix("layer ") {
            if let Some(v) = st.viewers.iter_mut().find(|v| v.peer.id() == p.id()) {
                v.wanted = rid.to_owned();
            }
            let pubp = st.publisher.clone();
            drop(st);
            if let Some((pp, mid)) = pubp {
                let r = pp.request_layer_keyframe(mid, rid, KeyframeRequestKind::Pli);
                eprintln!("sfu: layer {rid} asked: keyframe request {r:?}");
            }
            let _ = p.send(id, format!("ok {rid}").as_bytes(), false);
        } else if msg == "stats" {
            let s = st
                .counts
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join(" ");
            drop(st);
            let _ = p.send(id, s.as_bytes(), false);
        }
    }
    fn on_keyframe_request(&mut self, p: &Peer, r: &KeyframeRequest) {
        let st = self.0.lock().expect("lock");
        let rid = st
            .viewers
            .iter()
            .find(|v| v.peer.id() == p.id())
            .and_then(|v| {
                if r.mid == v.plain {
                    v.current.clone()
                } else {
                    r.rid.clone()
                }
            });
        let pubp = st.publisher.clone();
        drop(st);
        if let (Some((pp, mid)), Some(rid)) = (pubp, rid) {
            let _ = pp.request_layer_keyframe(mid, &rid, r.kind);
        }
    }
    fn on_close(&mut self, p: &Peer) {
        self.0
            .lock()
            .expect("lock")
            .viewers
            .retain(|v| v.peer.id() != p.id());
    }
}

fn respond(s: &mut TcpStream, r: Result<String, String>) {
    let resp = match r {
        Ok(body) => format!(
            "HTTP/1.1 201 Created\r\nContent-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        ),
        Err(m) => format!(
            "HTTP/1.1 400 Bad Request\r\nContent-Length: {}\r\n\r\n{m}",
            m.len()
        ),
    };
    let _ = s.write_all(resp.as_bytes());
}

fn sfu(udp: SocketAddr, http: SocketAddr, proxy: &[String]) {
    // Behind a lossy proxy: `<proxy-addr> loss-out=<%> [periodic]`.
    let public = match proxy.first() {
        Some(p) => {
            let public: SocketAddr = p.parse().expect("proxy addr");
            let loss = proxy
                .iter()
                .find_map(|o| o.strip_prefix("loss-out=").and_then(|v| v.parse().ok()))
                .unwrap_or(0);
            lossy_proxy(public, udp, 0, loss, proxy.iter().any(|o| o == "periodic"));
            public
        }
        None => udp,
    };
    let rtc = RtcServer::new(vec![public]).config(|| extras(only_webrtc::rtc_config()));
    let engine = Engine::builder()
        .listen(Listener::udp(udp).threads(1).serve(rtc.clone()))
        .build()
        .expect("engine");
    engine.start().expect("start");
    let st: SfuState = Arc::default();
    let l = TcpListener::bind(http).expect("http bind");
    eprintln!("sfu: udp {udp}, signalling http://{http}/");
    let mut pending: Option<Peer> = None;
    for s in l.incoming() {
        let Ok(mut s) = s else { continue };
        let (head, body) = read_http(&mut s);
        let path = head.split_whitespace().nth(1).unwrap_or("/").to_owned();
        let r = match path.as_str() {
            "/publish" => rtc
                .accept_offer(&body, Publisher(st.clone()))
                .map(|(_, answer)| answer)
                .map_err(|e| e.to_string()),
            "/view" => {
                let (mut sim, mut plain) = (None, None);
                rtc.create_offer(ViewerHandler(st.clone()), |api| {
                    sim = api
                        .add_simulcast_media(
                            MediaKind::Video,
                            Direction::SendOnly,
                            &["h", "m", "l"],
                            None,
                            None,
                        )
                        .ok();
                    plain = Some(api.add_media(MediaKind::Video, Direction::SendOnly, None, None));
                    api.add_channel("ctl");
                })
                .map(|(p, offer)| {
                    if let (Some(sim), Some(plain)) = (sim, plain) {
                        st.lock().expect("lock").viewers.push(Viewer {
                            peer: p.clone(),
                            sim,
                            plain,
                            current: None,
                            wanted: "l".into(),
                            offset: 0,
                            last_out: 0,
                        });
                    }
                    pending = Some(p);
                    offer
                })
                .map_err(|e| e.to_string())
            }
            "/view-answer" => match pending.take() {
                Some(p) => p
                    .accept_answer(&body)
                    .map(|()| String::new())
                    .map_err(|e| e.to_string()),
                None => Err("no viewer offer pending".into()),
            },
            _ => Err(format!("unknown path {path}")),
        };
        respond(&mut s, r);
    }
}

// ---- fec-server: FEC, RFC 8888, XR and TMMBR against a browser over a lossy proxy ----

/// Echoes media; asks for a maximum bitrate 3 s after connecting; prints events.
struct FecEcho {
    tmmbr: Option<u64>,
    connected: Option<Instant>,
    asked: bool,
    media: u64,
    keyframes: u64,
    /// Frames received per simulcast RID, and how many of them were whole (`contiguous`).
    rids: std::collections::BTreeMap<String, (u64, u64)>,
    /// Ask the browser for a keyframe this often, and when it was last asked.
    pli: Option<Duration>,
    last_pli: Option<Instant>,
}

impl PeerHandler for FecEcho {
    fn on_connected(&mut self, _p: &Peer) {
        self.connected = Some(Instant::now());
        eprintln!("server: connected");
    }
    fn on_media_data(&mut self, p: &Peer, d: &MediaData) {
        self.media += 1;
        if let Some(r) = &d.rid {
            let e = self.rids.entry(r.clone()).or_default();
            e.0 += 1;
            e.1 += u64::from(d.contiguous);
        }
        let _ = p.write_media(d.mid, d.pt, Instant::now(), d.time, &d.data);
        if let Some(every) = self.pli.filter(|_| d.codec == Some(Codec::Vp8)) {
            if self.last_pli.is_none_or(|t| t.elapsed() >= every) {
                self.last_pli = Some(Instant::now());
                let _ = p.request_keyframe(d.mid, KeyframeRequestKind::Pli);
            }
        }
        if let (Some(b), Some(t), false) = (self.tmmbr, self.connected, self.asked) {
            if t.elapsed() > Duration::from_secs(3) && d.codec.is_some_and(|c| c == Codec::Vp8) {
                self.asked = true;
                eprintln!("server: TMMBR {b} bps on {}", d.mid);
                let _ = p.request_max_bitrate(d.mid, Some(b));
            }
        }
    }
    fn on_keyframe_request(&mut self, p: &Peer, r: &KeyframeRequest) {
        // The echoed stream is the browser's: ask it for the keyframe.
        self.keyframes += 1;
        let _ = p.request_keyframe(r.mid, r.kind);
    }
    fn on_event(&mut self, _p: &Peer, e: &Event) {
        eprintln!("server: event {e:?}");
        if !self.rids.is_empty() {
            eprintln!("server: rid frames (all, whole) {:?}", self.rids);
        }
    }
    fn on_close(&mut self, _p: &Peer) {
        eprintln!(
            "server: peer closed after {} media samples, {} keyframe requests forwarded",
            self.media, self.keyframes
        );
    }
}

/// Forwards UDP between browser peer connections (at `public`) and the server (`inner`),
/// one upstream socket per browser address, dropping `loss_in` / `loss_out` percent of the RTP
/// (not RTCP, STUN or DTLS) towards each: at random, or with `periodic` exactly one packet in
/// every `100 / loss` (counted per direction and browser address).
fn lossy_proxy(public: SocketAddr, inner: SocketAddr, loss_in: u64, loss_out: u64, periodic: bool) {
    let outer = std::net::UdpSocket::bind(public).expect("proxy bind");
    fn is_rtp(d: &[u8]) -> bool {
        d.len() > 12 && (128..192).contains(&d[0]) && !(192..224).contains(&d[1])
    }
    let drop_it = move |x: &mut u64, loss: u64| {
        if periodic {
            *x += 1;
            return loss > 0 && *x % (100 / loss.clamp(1, 100)) == 0;
        }
        *x ^= *x << 13;
        *x ^= *x >> 7;
        *x ^= *x << 17;
        *x % 100 < loss
    };
    std::thread::spawn(move || {
        let mut ups: std::collections::HashMap<SocketAddr, (std::net::UdpSocket, u64)> =
            std::collections::HashMap::new();
        let mut buf = [0u8; 2048];
        let (mut fwd, mut drop) = (0u64, 0u64);
        while let Ok((n, from)) = outer.recv_from(&mut buf) {
            let (up, x) = ups.entry(from).or_insert_with(|| {
                // A new browser address: its own upstream socket, and its return path.
                let up = std::net::UdpSocket::bind("127.0.0.1:0").expect("proxy upstream");
                let (back, outer) = (
                    up.try_clone().expect("clone"),
                    outer.try_clone().expect("clone"),
                );
                std::thread::spawn(move || {
                    let mut buf = [0u8; 2048];
                    let mut x = 0x0fed_cba9_8765_4321u64;
                    let (mut fwd, mut drop) = (0u64, 0u64);
                    // Bursts of RTP: packets less than 300 us apart.
                    let (mut last, mut burst, mut max_burst, mut big) =
                        (Instant::now(), 0u64, 0u64, 0u64);
                    while let Ok((n, _)) = back.recv_from(&mut buf) {
                        if is_rtp(&buf[..n]) && drop_it(&mut x, loss_out) {
                            drop += 1;
                            continue;
                        }
                        if is_rtp(&buf[..n]) {
                            let now = Instant::now();
                            if now.duration_since(last) < Duration::from_micros(300) {
                                burst += 1;
                            } else {
                                big += u64::from(burst >= 6);
                                max_burst = max_burst.max(burst);
                                burst = 1;
                            }
                            last = now;
                        }
                        fwd += 1;
                        if (fwd + drop) % 200 == 0 {
                            eprintln!(
                                "proxy: out to {from} {fwd} forwarded, {drop} RTP dropped, \
                                 max burst {max_burst}, bursts of 6+ {big}"
                            );
                        }
                        let _ = outer.send_to(&buf[..n], from);
                    }
                });
                (up, 0x1234_5678_9abc_def1u64)
            });
            if is_rtp(&buf[..n]) && drop_it(x, loss_in) {
                drop += 1;
                continue;
            }
            fwd += 1;
            if (fwd + drop) % 2000 == 0 {
                eprintln!("proxy: in {fwd} forwarded, {drop} RTP dropped");
            }
            let _ = up.send_to(&buf[..n], inner);
        }
    });
}

fn fec_server(udp: SocketAddr, public: SocketAddr, http: SocketAddr, opts: &[String]) {
    let opt = |k: &str| {
        opts.iter().find_map(|o| match o.split_once('=') {
            Some((a, b)) if a == k => Some(b.to_owned()),
            None if o == k => Some(String::new()),
            _ => None,
        })
    };
    let num = |k: &str| opt(k).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
    let fec = match opt("fec").as_deref() {
        Some("ulpfec") => Some(FecMechanism::Ulpfec),
        Some("flexfec") => Some(FecMechanism::FlexFec),
        _ => None,
    };
    let min = num("min").min(255) as u8;
    let (ccfb, xr, bwe) = (
        opt("ccfb").is_some(),
        opt("xr").is_some(),
        opt("bwe").is_some(),
    );
    let tmmbr = opt("tmmbr").and_then(|v| v.parse::<u64>().ok());
    let periodic = opt("periodic").is_some();
    let (bwemax, pace, pli) = (num("bwemax"), opt("nopace").is_none(), num("pli"));
    // `direct`: no proxy (it would clear ECN marks); the server listens on <proxy-addr>.
    let direct = opt("direct").is_some();
    let udp = if direct {
        public
    } else {
        lossy_proxy(public, udp, num("loss-in"), num("loss-out"), periodic);
        udp
    };
    let rtc = RtcServer::new(vec![public]).config(move || {
        let mut c = extras(only_webrtc::rtc_config())
            .enable_fec(fec)
            .set_fec_protection(min, 128.max(min))
            .enable_ccfb(ccfb)
            .enable_rtcp_xr(xr)
            .enable_tmmbr(tmmbr.is_some())
            .set_stats_interval(Some(Duration::from_secs(1)));
        if bwe {
            c = c.enable_bwe(Some(1_000_000)).enable_pacing(pace);
            if bwemax > 0 {
                c = c.set_bwe_bounds(30_000, bwemax);
            }
        }
        c
    });
    let engine = Engine::builder()
        .listen(Listener::udp(udp).threads(1).serve(rtc.clone()))
        .build()
        .expect("engine");
    engine.start().expect("start");
    let l = TcpListener::bind(http).expect("http bind");
    eprintln!(
        "server: fec {fec:?} min {min} ccfb {ccfb} xr {xr} tmmbr {tmmbr:?}; udp {udp} via proxy {public}, signalling http://{http}/"
    );
    for s in l.incoming() {
        let Ok(mut s) = s else { continue };
        let (_, offer) = read_http(&mut s);
        let h = FecEcho {
            tmmbr,
            connected: None,
            asked: false,
            media: 0,
            keyframes: 0,
            rids: std::collections::BTreeMap::new(),
            pli: (pli > 0).then(|| Duration::from_millis(pli)),
            last_pli: None,
        };
        respond(
            &mut s,
            rtc.accept_offer(&offer, h)
                .map(|(_, a)| a)
                .map_err(|e| e.to_string()),
        );
    }
}
