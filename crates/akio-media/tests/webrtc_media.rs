//! WHIP and WHEP with WebRTC media (`akio_media::webrtc::RtcMedia`) end to end over loopback:
//! `akio-webrtc` `Endpoint`s are the WHIP publisher and the WHEP viewers, signalling goes over
//! HTTP to a `WhipServer`, media over an ICE-lite `RtcServer`. H.264, H.265, VP9 and AV1
//! frames come from the FLV test files, VP8 from an IVF file; Opus packets are synthetic (the
//! hub does not decode them).
#![cfg(feature = "webrtc")]

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{Receiver, Sender, channel},
    },
    thread,
    time::{Duration, Instant},
};

use akio::{Engine, Listener};
use akio_http::{Router, serve};
use akio_media::{
    Codec, Hub, PeerInfo, Track,
    av::{MILLISECOND, Packet, SECOND, to_ticks},
    codec::{av1, h264, vp8, vp9},
    flv::{Decoder, Demuxer, Event},
    webrtc::{RtcMedia, RtcMediaConfig, rtc_config},
    whip::{WhipConfig, WhipServer},
};
use akio_webrtc::{
    Codec as RtcCodec, Direction, Endpoint, Frequency, KeyframeRequest, KeyframeRequestKind,
    MediaData, MediaKind, MediaTime, Mid, Peer, PeerHandler,
};

const H264_FLV: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/h264_aac.flv");
const H265_FLV: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/h265_aac.flv");
const VP9_FLV: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/vp9_opus.flv");
const AV1_FLV: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/av1_opus.flv");
const VP8_IVF: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/vp8.ivf");
const T: Duration = Duration::from_secs(15);

struct Setup {
    engine: Arc<Engine>,
    hub: Hub,
    http: SocketAddr,
    whip: WhipServer,
    clients: Mutex<Vec<Endpoint>>,
}

impl Setup {
    /// A client endpoint of its own for each peer: an `Endpoint` routes what comes from an
    /// address to the first of its peers that sent there.
    fn client(&self) -> Endpoint {
        let ep = Endpoint::bind(&self.engine, "127.0.0.1:0".parse().unwrap())
            .unwrap()
            .config(rtc_config);
        self.clients.lock().unwrap().push(ep.clone()); // its peers need it alive
        ep
    }
}

fn setup() -> Setup {
    let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let udp = probe.local_addr().unwrap();
    drop(probe);
    let hub = Hub::default();
    let rtc = RtcMedia::rtc_server(vec![udp]);
    let mut cfg = RtcMediaConfig::default();
    cfg.track_timeout = Duration::from_secs(3);
    let whip = WhipServer::new(
        hub.clone(),
        Arc::new(RtcMedia::new(rtc.clone(), cfg)),
        WhipConfig::default(),
    );
    let engine = Arc::new(
        Engine::builder()
            .udp_client_threads(1)
            .listen(Listener::udp(udp).threads(1).serve(rtc))
            .listen(
                Listener::tcp("127.0.0.1:0".parse().unwrap())
                    .serve(serve(whip.routes(Router::new()))),
            )
            .build()
            .unwrap(),
    );
    engine.start().unwrap();
    let http = *engine
        .local_addrs()
        .iter()
        .find(|a| a.port() != udp.port())
        .unwrap();
    Setup {
        engine,
        hub,
        http,
        whip,
        clients: Mutex::default(),
    }
}

fn http(addr: SocketAddr, req: &str) -> (u16, String, String) {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(req.as_bytes()).unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    let text = String::from_utf8_lossy(&out).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status = head
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    (status, head.to_owned(), body.to_owned())
}

/// POSTs an offer; the status, the session resource and the answer.
fn post_offer(addr: SocketAddr, path: &str, sdp: &str) -> (u16, String, String) {
    let (status, head, body) = http(
        addr,
        &format!(
            "POST {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{sdp}",
            sdp.len()
        ),
    );
    let loc = head
        .lines()
        .find_map(|l| l.strip_prefix("Location: "))
        .unwrap_or("")
        .trim()
        .to_owned();
    (status, loc, body)
}

fn delete(addr: SocketAddr, loc: &str) -> u16 {
    http(
        addr,
        &format!("DELETE {loc} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"),
    )
    .0
}

fn wait(what: &str, mut f: impl FnMut() -> bool) {
    let end = Instant::now() + T;
    while !f() {
        assert!(Instant::now() < end, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(10));
    }
}

/// The VP8 track and frames of an IVF file (25 fps).
fn read_ivf(path: &str) -> (Vec<Track>, Vec<Packet>) {
    let data = std::fs::read(path).unwrap();
    assert_eq!(&data[..4], b"DKIF");
    let mut pos = usize::from(u16::from_le_bytes([data[6], data[7]]));
    let mut packets = Vec::new();
    while pos + 12 <= data.len() {
        let n = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        let pts = i64::from_le_bytes(data[pos + 4..pos + 12].try_into().unwrap());
        let frame = data[pos + 12..pos + 12 + n].to_vec();
        let t = pts * 40 * MILLISECOND;
        packets.push(Packet::new(0, t, t, vp8::is_keyframe(&frame), frame));
        pos += 12 + n;
    }
    let track = Track::video_from_keyframe(Codec::Vp8, &packets[0].data).unwrap();
    (vec![track], packets)
}

/// The tracks and packets of an FLV (or IVF) file.
fn read_flv(path: &str) -> (Vec<Track>, Vec<Packet>) {
    if path.ends_with(".ivf") {
        return read_ivf(path);
    }
    let data = std::fs::read(path).unwrap();
    let mut dm = Demuxer::new();
    let mut dec = Decoder::new();
    let mut tracks = Vec::new();
    let mut packets = Vec::new();
    for tag in dm.feed(&data).unwrap() {
        for ev in dec.write(tag.tag_type, tag.ts, &tag.body) {
            match ev {
                Event::Tracks(t) => tracks = t.to_vec(),
                Event::Packet(p) => packets.push(p),
                _ => {}
            }
        }
    }
    (tracks, packets)
}

/// The frame WebRTC sends: an AVCC access unit as Annex B, with the configuration's parameter
/// sets before keyframes; VP8, VP9 and AV1 as they are.
fn annexb(track: &Track, p: &Packet) -> Vec<u8> {
    if !matches!(track.codec, Codec::H264 | Codec::H265) {
        return p.data.clone();
    }
    let mut out = Vec::new();
    if p.keyframe {
        let sets: Vec<Vec<u8>> = if track.codec == Codec::H265 {
            let c = akio_media::codec::h265::Config::parse(&track.config).unwrap();
            c.vps.into_iter().chain(c.sps).chain(c.pps).collect()
        } else {
            let c = h264::Config::parse(&track.config).unwrap();
            c.sps.into_iter().chain(c.pps).collect()
        };
        for s in sets {
            out.extend_from_slice(&[0, 0, 0, 1]);
            out.extend_from_slice(&s);
        }
    }
    h264::avcc_to_annexb(&p.data, &mut out);
    out
}

#[derive(Debug)]
enum Got {
    Connected,
    Keyframe(Instant),
    Media(Mid, Option<RtcCodec>, Arc<[u8]>),
    Closed,
}

struct Client(Mutex<Sender<Got>>);

impl PeerHandler for Client {
    fn on_connected(&mut self, _p: &Peer) {
        let _ = self.0.lock().unwrap().send(Got::Connected);
    }
    fn on_keyframe_request(&mut self, _p: &Peer, _r: &KeyframeRequest) {
        let _ = self.0.lock().unwrap().send(Got::Keyframe(Instant::now()));
    }
    fn on_media_data(&mut self, _p: &Peer, d: &MediaData) {
        let _ = self
            .0
            .lock()
            .unwrap()
            .send(Got::Media(d.mid, d.codec, d.data.clone()));
    }
    fn on_close(&mut self, _p: &Peer) {
        let _ = self.0.lock().unwrap().send(Got::Closed);
    }
}

fn next(rx: &Receiver<Got>, what: &str, mut f: impl FnMut(&Got) -> bool) -> Got {
    let end = Instant::now() + T;
    loop {
        let left = end.saturating_duration_since(Instant::now());
        let g = rx
            .recv_timeout(left)
            .unwrap_or_else(|_| panic!("timed out waiting for {what}"));
        if f(&g) {
            return g;
        }
    }
}

/// A WHIP publisher: an `Endpoint` peer sending the video of an FLV file (looped) and
/// synthetic Opus, until stopped.
struct Publishing {
    peer: Peer,
    location: String,
    events: Receiver<Got>,
    stop: Arc<AtomicBool>,
    sender: Option<thread::JoinHandle<()>>,
}

impl Drop for Publishing {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(h) = self.sender.take() {
            let _ = h.join();
        }
        self.peer.close();
    }
}

fn publish(s: &Setup, path: &str, flv: &str, with_audio: bool) -> Publishing {
    let (tracks, packets) = read_flv(flv);
    let vi = tracks.iter().position(Track::is_video).unwrap();
    let vtrack = tracks[vi].clone();
    let codec = match vtrack.codec {
        Codec::H265 => RtcCodec::H265,
        Codec::Vp8 => RtcCodec::Vp8,
        Codec::Vp9 => RtcCodec::Vp9,
        Codec::Av1 => RtcCodec::Av1,
        _ => RtcCodec::H264,
    };
    let (tx, rx) = channel();
    let (mut video, mut audio) = (None, None);
    let (peer, offer) = s
        .client()
        .create_offer(Client(Mutex::new(tx)), |api| {
            video = Some(api.add_media(MediaKind::Video, Direction::SendOnly, None, None));
            if with_audio {
                audio = Some(api.add_media(MediaKind::Audio, Direction::SendOnly, None, None));
            }
        })
        .unwrap();
    let (status, location, answer) = post_offer(s.http, &format!("/whip/{path}"), &offer);
    assert_eq!(status, 201, "{answer}");
    peer.accept_answer(&answer).unwrap();
    next(&rx, "WHIP connected", |g| matches!(g, Got::Connected));
    // The ingest asks for a keyframe as soon as it is connected.
    next(&rx, "the first PLI", |g| matches!(g, Got::Keyframe(_)));
    let video = video.unwrap();
    let vpt = peer
        .payload_type(video, codec)
        .expect("video codec negotiated");
    let apt = audio.map(|m| (m, peer.payload_type(m, RtcCodec::Opus).unwrap()));
    let stop = Arc::new(AtomicBool::new(false));
    let (p2, stop2) = (peer.clone(), stop.clone());
    let sender = thread::spawn(move || {
        let frames: Vec<&Packet> = packets.iter().filter(|p| p.track == vi).collect();
        let first_key = frames.iter().position(|p| p.keyframe).unwrap();
        let span = frames.last().unwrap().dts - frames[first_key].dts + SECOND / 25;
        let mut round = 0i64;
        let mut opus_ticks = 0u64;
        let start = Instant::now();
        while !stop2.load(Ordering::Acquire) {
            for p in &frames[first_key..] {
                if stop2.load(Ordering::Acquire) {
                    return;
                }
                let t = p.dts - frames[first_key].dts + round * span;
                let ticks = to_ticks(t, 90_000) as u64;
                let _ = p2.write_media(
                    video,
                    vpt,
                    Instant::now(),
                    MediaTime::new(ticks, Frequency::NINETY_KHZ),
                    &annexb(&vtrack, p),
                );
                if let Some((amid, apt)) = apt {
                    // 20 ms Opus packets up to the video's time.
                    while opus_ticks * 1_000_000_000 / 48_000 <= t as u64 {
                        let _ = p2.write_media(
                            amid,
                            apt,
                            Instant::now(),
                            MediaTime::new(opus_ticks, Frequency::FORTY_EIGHT_KHZ),
                            &[0xfc, 0xff, 0xfe, (opus_ticks / 960) as u8],
                        );
                        opus_ticks += 960;
                    }
                }
                // Faster than real time, slow enough for loopback UDP buffers.
                let due = start + Duration::from_nanos((t / 4) as u64);
                if let Some(d) = due.checked_duration_since(Instant::now()) {
                    thread::sleep(d);
                }
            }
            round += 1;
        }
    });
    Publishing {
        peer,
        location,
        events: rx,
        stop,
        sender: Some(sender),
    }
}

/// A WHEP viewer: an `Endpoint` peer receiving `path`.
fn play(
    s: &Setup,
    path: &str,
    video: bool,
    audio: bool,
) -> (u16, Peer, String, Receiver<Got>, Option<Mid>) {
    let (tx, rx) = channel();
    let mut vmid = None;
    let (peer, offer) = s
        .client()
        .create_offer(Client(Mutex::new(tx)), |api| {
            if video {
                vmid = Some(api.add_media(MediaKind::Video, Direction::RecvOnly, None, None));
            }
            if audio {
                api.add_media(MediaKind::Audio, Direction::RecvOnly, None, None);
            }
        })
        .unwrap();
    let (status, location, answer) = post_offer(s.http, &format!("/whep/{path}"), &offer);
    if status == 201 {
        peer.accept_answer(&answer).unwrap();
    } else {
        peer.close();
    }
    (status, peer, location, rx, vmid)
}

fn nal_types(annexb: &[u8], h265: bool) -> Vec<u8> {
    h264::split_annexb(annexb)
        .iter()
        .filter_map(|n| n.first())
        .map(|&b| if h265 { (b >> 1) & 0x3f } else { b & 0x1f })
        .collect()
}

#[test]
fn whip_publish_whep_play_and_keyframe_round_trip() {
    let s = setup();
    let pubr = publish(&s, "live/s", H264_FLV, true);

    // The stream goes live with H.264 (configuration from the in-band SPS/PPS) and Opus.
    wait("the stream live", || {
        s.hub
            .stream_info("live/s")
            .is_some_and(|i| i.publishing && i.packets_in > 20)
    });
    let info = s.hub.stream_info("live/s").unwrap();
    let codecs: Vec<Codec> = info.tracks.iter().map(|t| t.codec).collect();
    assert_eq!(codecs, vec![Codec::H264, Codec::Opus]);
    let v = &info.tracks[0];
    let cfg = h264::Config::parse(&v.config).unwrap();
    assert_eq!(cfg.sps.len(), 1);
    assert!(v.width > 0 && v.height > 0, "{v:?}");
    assert_eq!(
        (info.tracks[1].sample_rate, info.tracks[1].channels),
        (48_000, 2)
    );

    // Hub packets: AVCC video with keyframes, monotonic times.
    let got: Arc<Mutex<Vec<Arc<Packet>>>> = Arc::default();
    struct Tap(Arc<Mutex<Vec<Arc<Packet>>>>);
    impl akio_media::Sink for Tap {
        fn on_tracks(&mut self, _t: &akio_media::Tracks) {}
        fn on_packet(&mut self, p: &Arc<Packet>) {
            self.0.lock().unwrap().push(p.clone());
        }
    }
    let tap = s
        .hub
        .subscribe(
            "live/s",
            Tap(got.clone()),
            akio_media::SubscribeOptions::default(),
        )
        .unwrap();
    wait("hub packets", || got.lock().unwrap().len() > 60);
    {
        let g = got.lock().unwrap();
        let vids: Vec<&Arc<Packet>> = g.iter().filter(|p| p.track == 0).collect();
        assert!(vids[0].keyframe, "a subscriber starts at a keyframe");
        assert!(vids.iter().all(|p| !h264::avcc_nalus(&p.data).is_empty()));
        assert!(vids.windows(2).all(|w| w[1].dts >= w[0].dts));
        let auds: Vec<&Arc<Packet>> = g.iter().filter(|p| p.track == 1).collect();
        assert!(!auds.is_empty() && auds.windows(2).all(|w| w[1].dts >= w[0].dts));
        assert_eq!(auds[0].data[..3], [0xfc, 0xff, 0xfe]);
    }
    drop(tap);

    // A WHEP viewer gets H.264 (starting with SPS, PPS and an IDR) and Opus.
    let (status, viewer, loc, rx, vmid) = play(&s, "live/s", true, true);
    assert_eq!(status, 201);
    next(&rx, "WHEP connected", |g| matches!(g, Got::Connected));
    let vmid = vmid.unwrap();
    let Got::Media(_, codec, first) = next(
        &rx,
        "video",
        |g| matches!(g, Got::Media(m, ..) if *m == vmid),
    ) else {
        unreachable!()
    };
    assert_eq!(codec, Some(RtcCodec::H264));
    let types = nal_types(&first, false);
    assert!(
        types.starts_with(&[7, 8]) && types.contains(&5),
        "the first frame is a keyframe with its parameter sets: {types:?}"
    );
    next(
        &rx,
        "audio",
        |g| matches!(g, Got::Media(m, Some(RtcCodec::Opus), d) if *m != vmid && d[..3] == [0xfc, 0xff, 0xfe]),
    );
    let mut frames = 0;
    while frames < 30 {
        if let Got::Media(m, ..) = next(&rx, "frames", |g| matches!(g, Got::Media(..))) {
            frames += usize::from(m == vmid);
        }
    }

    // The viewer's PLI reaches the WHIP publisher as a PLI (past the hub's 500 ms throttle).
    thread::sleep(Duration::from_millis(700));
    while pubr.events.try_recv().is_ok() {}
    let asked = Instant::now();
    viewer
        .request_keyframe(vmid, KeyframeRequestKind::Pli)
        .unwrap();
    next(
        &pubr.events,
        "the PLI at the publisher",
        |g| matches!(g, Got::Keyframe(t) if *t >= asked),
    );

    // DELETE ends the viewer's session; the stream stays.
    assert_eq!(delete(s.http, &loc), 200);
    next(&rx, "viewer closed", |g| matches!(g, Got::Closed));
    wait("viewer unsubscribed", || {
        s.hub
            .stream_info("live/s")
            .is_some_and(|i| i.subscribers == 0)
    });
    assert!(s.hub.stream_info("live/s").unwrap().publishing);

    // A second viewer; then the publisher's DELETE unpublishes and closes the viewer.
    let (status, _viewer2, _loc2, rx2, vmid2) = play(&s, "live/s", true, false);
    assert_eq!(status, 201);
    let vmid2 = vmid2.unwrap();
    next(
        &rx2,
        "second viewer video",
        |g| matches!(g, Got::Media(m, ..) if *m == vmid2),
    );
    assert_eq!(delete(s.http, &pubr.location), 200);
    wait("unpublished", || {
        s.hub.stream_info("live/s").is_none_or(|i| !i.publishing)
    });
    next(&rx2, "viewer closed with the stream", |g| {
        matches!(g, Got::Closed)
    });
    drop(pubr);
    wait("sessions gone", || s.whip.sessions() == 0);
    s.engine.shutdown();
    s.engine.wait();
}

#[test]
fn whip_h265_video_only_goes_live_with_hvcc() {
    let s = setup();
    let _pubr = publish(&s, "live/h265", H265_FLV, false);
    wait("the H.265 stream live", || {
        s.hub
            .stream_info("live/h265")
            .is_some_and(|i| i.publishing && i.packets_in > 10)
    });
    let info = s.hub.stream_info("live/h265").unwrap();
    assert_eq!(info.tracks.len(), 1);
    assert_eq!(info.tracks[0].codec, Codec::H265);
    let c = akio_media::codec::h265::Config::parse(&info.tracks[0].config).unwrap();
    assert!(!c.vps.is_empty() && !c.sps.is_empty() && !c.pps.is_empty());
    assert!(info.tracks[0].width > 0);
    // And plays back over WHEP.
    let (status, _v, _loc, rx, vmid) = play(&s, "live/h265", true, true);
    assert_eq!(status, 201);
    let vmid = vmid.unwrap();
    let Got::Media(_, codec, first) = next(
        &rx,
        "H.265 video",
        |g| matches!(g, Got::Media(m, ..) if *m == vmid),
    ) else {
        unreachable!()
    };
    assert_eq!(codec, Some(RtcCodec::H265));
    let types = nal_types(&first, true);
    assert!(types.starts_with(&[32, 33, 34]), "{types:?}");
    s.engine.shutdown();
    s.engine.wait();
}

/// RTMP-style ingest (packets written to a hub publisher: H.264 + AAC) out over WHEP: video
/// plays, AAC is not sent; an offer that takes no codec of the stream gets 406, so does a WHIP
/// offer with only G.722.
#[test]
fn hub_publisher_to_whep_and_unsupported_offers() {
    let s = setup();
    let (tracks, packets) = read_flv(H264_FLV);
    assert_eq!(tracks[1].codec, Codec::Aac);
    let publisher = s
        .hub
        .publish("live/r", tracks.into(), PeerInfo::default())
        .unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let writer = thread::spawn(move || {
        let span = packets.last().unwrap().dts + SECOND / 25;
        let mut round = 0;
        while !stop2.load(Ordering::Acquire) {
            for p in &packets {
                let mut p = p.clone();
                p.dts += round * span;
                p.pts += round * span;
                publisher.write(p);
                thread::sleep(Duration::from_millis(2));
            }
            round += 1;
        }
    });

    // Audio only: AAC cannot go to WebRTC.
    let (status, ..) = play(&s, "live/r", false, true);
    assert_eq!(status, 406);
    let (status, _v, _loc, rx, vmid) = play(&s, "live/r", true, true);
    assert_eq!(status, 201);
    let vmid = vmid.unwrap();
    let mut keyframe = false;
    let mut n = 0;
    while n < 20 {
        if let Got::Media(m, codec, d) = next(&rx, "video", |g| matches!(g, Got::Media(..))) {
            assert_eq!(m, vmid, "only video is sent");
            assert_eq!(codec, Some(RtcCodec::H264));
            keyframe |= nal_types(&d, false).contains(&5);
            n += 1;
        }
    }
    assert!(keyframe);

    // A WHIP offer whose only codec is G.722 (an Opus offer renamed): 406, and the path
    // stays free.
    let ep = Endpoint::bind(&s.engine, "127.0.0.1:0".parse().unwrap())
        .unwrap()
        .config(|| akio_webrtc::rtc_config().clear_codecs().enable_opus(true));
    let (tx, _rx) = channel();
    let (p, offer) = ep
        .create_offer(Client(Mutex::new(tx)), |api| {
            api.add_media(MediaKind::Audio, Direction::SendOnly, None, None);
        })
        .unwrap();
    let offer = offer.replace("opus/48000/2", "G722/8000");
    assert!(offer.contains("G722"), "{offer}");
    let (status, _, body) = post_offer(s.http, "/whip/live/g722", &offer);
    assert_eq!(status, 406, "{body}");
    p.close();
    assert!(s.hub.stream_info("live/g722").is_none_or(|i| !i.publishing));

    stop.store(true, Ordering::Release);
    writer.join().unwrap();
    s.engine.shutdown();
    s.engine.wait();
}

/// VP8, VP9 and AV1 over WHIP: the stream goes live with the configuration record and size
/// from the first keyframe, keyframes are those of the bitstream, and a WHEP viewer gets the
/// same codec, starting at a keyframe, frames byte for byte.
#[test]
fn whip_vp8_vp9_av1_publish_and_whep_play() {
    let s = setup();
    for (src, codec, rtc) in [
        (VP8_IVF, Codec::Vp8, RtcCodec::Vp8),
        (VP9_FLV, Codec::Vp9, RtcCodec::Vp9),
        (AV1_FLV, Codec::Av1, RtcCodec::Av1),
    ] {
        let path = format!("live/{}", codec.name().to_lowercase());
        let pubr = publish(&s, &path, src, false);
        wait("the stream live", || {
            s.hub
                .stream_info(&path)
                .is_some_and(|i| i.publishing && i.packets_in > 10)
        });
        let info = s.hub.stream_info(&path).unwrap();
        assert_eq!(info.tracks.len(), 1, "{codec}");
        let t = &info.tracks[0];
        assert_eq!((t.codec, t.width, t.height), (codec, 320, 240));
        let want = read_flv(src).0[0].codec_string();
        assert_eq!(
            t.codec_string().map(|c| c[..9].to_owned()),
            want.map(|c| c[..9].to_owned())
        );
        let is_key = |d: &[u8]| match codec {
            Codec::Vp8 => vp8::is_keyframe(d),
            Codec::Vp9 => vp9::is_keyframe(d),
            _ => av1::is_keyframe(d),
        };
        let (status, viewer, _loc, rx, vmid) = play(&s, &path, true, false);
        assert_eq!(status, 201, "{codec}");
        let vmid = vmid.unwrap();
        let Got::Media(_, got, first) = next(
            &rx,
            "video",
            |g| matches!(g, Got::Media(m, ..) if *m == vmid),
        ) else {
            unreachable!()
        };
        assert_eq!(got, Some(rtc), "{codec}");
        assert!(is_key(&first), "{codec}: WHEP starts at a keyframe");
        let (_, frames) = read_flv(src);
        let originals: Vec<&[u8]> = frames.iter().map(|p| p.data.as_slice()).collect();
        let mut n = 0;
        while n < 20 {
            if let Got::Media(_, _, d) = next(&rx, "frames", |g| matches!(g, Got::Media(..))) {
                assert!(originals.contains(&&d[..]), "{codec}: frame {n} altered");
                n += 1;
            }
        }
        viewer.close();
        drop(pubr);
    }
    s.engine.shutdown();
    s.engine.wait();
}

/// Trickled candidates reach the peer (PATCH 204), bad ones are refused (400).
#[test]
fn trickle_patch() {
    let s = setup();
    let (tx, _rx) = channel();
    let (peer, offer) = s
        .client()
        .create_offer(Client(Mutex::new(tx)), |api| {
            api.add_media(MediaKind::Audio, Direction::SendOnly, None, None);
        })
        .unwrap();
    let (status, loc, _) = post_offer(s.http, "/whip/live/t", &offer);
    assert_eq!(status, 201);
    let patch = |frag: &str| {
        http(
            s.http,
            &format!(
                "PATCH {loc} HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Type: application/trickle-ice-sdpfrag\r\nContent-Length: {}\r\n\r\n{frag}",
                frag.len()
            ),
        )
        .0
    };
    assert_eq!(
        patch(
            "a=ice-ufrag:x\r\na=mid:0\r\na=candidate:1 1 udp 2130706431 127.0.0.1 40000 typ host\r\na=end-of-candidates\r\n"
        ),
        204
    );
    assert_eq!(patch("a=candidate:garbage\r\n"), 400);
    peer.close();
    assert_eq!(delete(s.http, &loc), 200);
    s.engine.shutdown();
    s.engine.wait();
}
