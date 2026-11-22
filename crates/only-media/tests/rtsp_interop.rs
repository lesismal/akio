//! RTSP server tests: a hand-written client against hub-published packets, and ffmpeg /
//! ffprobe as publisher and player (skipped when they are not installed): H.264, H.265, VP8,
//! VP9 and AV1 (with an ffmpeg that packetizes it).

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    process::{Child, Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};

use only::{Engine, Listener};
use only_media::{
    Codec, Hub, Packet, PeerInfo, Track,
    av::MILLISECOND,
    codec::h264,
    rtp::Depacketizer,
    rtsp::{RtspConfig, RtspServer, message::interleaved},
    sdp,
};

const SPS: &[u8] = &[
    0x67, 0x64, 0x00, 0x0d, 0xac, 0xd9, 0x41, 0x41, 0xfb, 0x01, 0x10, 0x00, 0x00, 0x03, 0x00, 0x10,
    0x00, 0x00, 0x03, 0x03, 0x20, 0xf1, 0x42, 0x99, 0x60,
];
const PPS: &[u8] = &[0x68, 0xeb, 0xe3, 0xcb, 0x22, 0xc0];

fn start(cfg: RtspConfig) -> (Hub, Arc<Engine>, SocketAddr) {
    let hub = Hub::default();
    let srv = RtspServer::new(hub.clone(), cfg);
    srv.listen_udp("127.0.0.1:0".parse().unwrap()).unwrap();
    let engine = Arc::new(
        Engine::builder()
            .listen(Listener::tcp("127.0.0.1:0".parse().unwrap()).serve(srv))
            .build()
            .unwrap(),
    );
    engine.start().unwrap();
    let addr = engine.local_addrs()[0];
    (hub, engine, addr)
}

/// A minimal blocking RTSP client.
struct Client {
    s: TcpStream,
    buf: Vec<u8>,
    cseq: u32,
}

impl Client {
    fn connect(addr: SocketAddr) -> Client {
        let s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        Client {
            s,
            buf: Vec::new(),
            cseq: 0,
        }
    }

    fn fill(&mut self) {
        let mut b = vec![0u8; 65536];
        let n = self.s.read(&mut b).expect("read");
        assert!(n > 0, "closed");
        self.buf.extend_from_slice(&b[..n]);
    }

    fn request(
        &mut self,
        method: &str,
        url: &str,
        headers: &str,
        body: &str,
    ) -> (u16, String, String) {
        self.cseq += 1;
        let req = format!(
            "{method} {url} RTSP/1.0\r\nCSeq: {}\r\n{headers}{}\r\n{body}",
            self.cseq,
            if body.is_empty() {
                String::new()
            } else {
                format!("Content-Length: {}\r\n", body.len())
            }
        );
        self.s.write_all(req.as_bytes()).unwrap();
        loop {
            // skip interleaved frames ahead of the response
            while self.buf.first() == Some(&b'$') && self.buf.len() >= 4 {
                let n = 4 + usize::from(u16::from_be_bytes([self.buf[2], self.buf[3]]));
                if self.buf.len() < n {
                    break;
                }
                self.buf.drain(..n);
            }
            if let Some(end) = self.buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&self.buf[..end]).into_owned();
                let len = head
                    .lines()
                    .find_map(|l| l.strip_prefix("Content-Length: "))
                    .map_or(0, |v| v.trim().parse().unwrap());
                while self.buf.len() < end + 4 + len {
                    self.fill();
                }
                let body = String::from_utf8_lossy(&self.buf[end + 4..end + 4 + len]).into_owned();
                self.buf.drain(..end + 4 + len);
                let status = head[9..12].parse().unwrap();
                return (status, head, body);
            }
            self.fill();
        }
    }

    fn frame(&mut self) -> (u8, Vec<u8>) {
        loop {
            if self.buf.len() >= 4 && self.buf[0] == b'$' {
                let n = usize::from(u16::from_be_bytes([self.buf[2], self.buf[3]]));
                if self.buf.len() >= 4 + n {
                    let ch = self.buf[1];
                    let data = self.buf[4..4 + n].to_vec();
                    self.buf.drain(..4 + n);
                    return (ch, data);
                }
            }
            self.fill();
        }
    }
}

fn video_packets() -> Vec<Packet> {
    let mut v = Vec::new();
    for i in 0..50i64 {
        let key = i % 25 == 0;
        let nal: Vec<u8> = std::iter::once(if key { 0x65 } else { 0x41 })
            .chain((0..(if key { 4000 } else { 300 })).map(|b| (b + i) as u8))
            .collect();
        let t = i * 40 * MILLISECOND;
        v.push(Packet::new(0, t, t, key, h264::to_avcc([&nal[..]])));
    }
    v
}

#[test]
fn hub_to_rtsp_player_over_tcp() {
    let (hub, engine, addr) = start(RtspConfig::default());
    let track = Track::video(Codec::H264, h264::Config::from_sets(SPS, PPS).encode());
    let p = hub
        .publish(
            "live/t",
            Arc::from(vec![track.clone(), Track::aac(vec![0x12, 0x10])]),
            PeerInfo::default(),
        )
        .unwrap();
    let pkts = video_packets();
    for pk in &pkts[..10] {
        p.write(pk.clone());
    }
    let mut c = Client::connect(addr);
    assert_eq!(c.request("OPTIONS", "rtsp://h/live/t", "", "").0, 200);
    assert_eq!(
        c.request("DESCRIBE", &format!("rtsp://{addr}/live/none"), "", "")
            .0,
        404
    );
    let (st, head, body) = c.request(
        "DESCRIBE",
        &format!("rtsp://{addr}/live/t"),
        "Accept: application/sdp\r\n",
        "",
    );
    assert_eq!(st, 200, "{head}");
    let sdp = sdp::Session::parse(&body).unwrap();
    assert_eq!(sdp.media.len(), 2);
    let (t0, _) = sdp::media_track(&sdp.media[0]).unwrap();
    assert_eq!((t0.width, t0.height), (320, 240));
    let (st, head, _) = c.request(
        "SETUP",
        &format!("rtsp://{addr}/live/t/trackID=0"),
        "Transport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n",
        "",
    );
    assert_eq!(st, 200, "{head}");
    assert!(head.contains("interleaved=0-1"));
    let session = head
        .lines()
        .find_map(|l| l.strip_prefix("Session: "))
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let (st, _, _) = c.request(
        "PLAY",
        &format!("rtsp://{addr}/live/t"),
        &format!("Session: {session}\r\n"),
        "",
    );
    assert_eq!(st, 200);
    for pk in &pkts[10..] {
        p.write(pk.clone());
    }
    let mut d = Depacketizer::new(&track);
    let mut got = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    while got.len() < 40 && Instant::now() < deadline {
        let (ch, data) = c.frame();
        if ch == 0 {
            d.push(&data, &mut got).unwrap();
        } else {
            assert_eq!(data[1], 200, "RTCP SR on channel 1");
        }
    }
    // The cached GOP (from the keyframe at 0) and everything after, in order.
    assert!(got.len() >= 39, "{}", got.len());
    assert!(got[0].keyframe);
    assert_eq!(
        h264::avcc_nalus(&got[0].data)[2],
        h264::avcc_nalus(&pkts[0].data)[0]
    );
    for (g, o) in got.iter().zip(&pkts) {
        assert_eq!(
            h264::avcc_nalus(&g.data).last(),
            h264::avcc_nalus(&o.data).last()
        );
    }
    assert!((got[25].pts - 25 * 40 * MILLISECOND).abs() < MILLISECOND);
    assert_eq!(
        c.request(
            "TEARDOWN",
            "rtsp://h/live/t",
            &format!("Session: {session}\r\n"),
            ""
        )
        .0,
        200
    );
    engine.shutdown();
}

#[test]
fn announce_record_over_tcp_publishes_into_the_hub() {
    let (hub, engine, addr) = start(RtspConfig::default());
    let track = Track::video(Codec::H264, h264::Config::from_sets(SPS, PPS).encode());
    let mut s = sdp::Session::new("rec");
    s.media
        .push(sdp::track_media(&track, 96, "streamid=0").unwrap());
    let body = s.to_string();
    let mut c = Client::connect(addr);
    let (st, _, _) = c.request(
        "ANNOUNCE",
        &format!("rtsp://{addr}/live/r"),
        "Content-Type: application/sdp\r\n",
        &body,
    );
    assert_eq!(st, 200);
    // A second publisher of the same path is refused.
    let mut c2 = Client::connect(addr);
    assert_eq!(
        c2.request(
            "ANNOUNCE",
            &format!("rtsp://{addr}/live/r"),
            "Content-Type: application/sdp\r\n",
            &body
        )
        .0,
        453
    );
    let (st, head, _) = c.request(
        "SETUP",
        &format!("rtsp://{addr}/live/r/streamid=0"),
        "Transport: RTP/AVP/TCP;unicast;interleaved=0-1;mode=record\r\n",
        "",
    );
    assert_eq!(st, 200, "{head}");
    assert_eq!(
        c.request(
            "RECORD",
            &format!("rtsp://{addr}/live/r"),
            "Session: x\r\n",
            ""
        )
        .0,
        200
    );
    let mut pz = only_media::rtp::Packetizer::new(&track, 96);
    let mut wire = Vec::new();
    for pk in video_packets() {
        let mut out = Vec::new();
        pz.packetize(&pk, &mut out);
        for r in out {
            interleaved(0, &r, &mut wire);
        }
    }
    c.s.write_all(&wire).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(i) = hub.stream_info("live/r") {
            if i.publishing && i.packets_in >= 49 {
                assert_eq!(i.tracks[0].codec, Codec::H264);
                assert_eq!(i.publisher.protocol, "rtsp");
                break;
            }
        }
        assert!(Instant::now() < deadline, "{:?}", hub.stream_info("live/r"));
        std::thread::sleep(Duration::from_millis(10));
    }
    drop(c);
    let deadline = Instant::now() + Duration::from_secs(5);
    while hub.stream_info("live/r").is_some_and(|i| i.publishing) {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    }
    engine.shutdown();
}

#[test]
fn digest_auth_challenge() {
    let mut cfg = RtspConfig::default();
    cfg.credentials = Some(Arc::new(|u: &str| (u == "admin").then(|| "pw".to_owned())));
    let (_hub, engine, addr) = start(cfg);
    let mut c = Client::connect(addr);
    let (st, head, _) = c.request("DESCRIBE", &format!("rtsp://{addr}/live/x"), "", "");
    assert_eq!(st, 401);
    assert!(head.contains("WWW-Authenticate: Digest realm=\"only-media\""));
    engine.shutdown();
}

// ---- ffmpeg interop -----------------------------------------------------------------------

fn have(tool: &str) -> bool {
    Command::new(tool)
        .arg("-version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

struct Kill(Child);

impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn publish(url: &str, transport: &str, vcodec: &str, acodec: &str) -> Kill {
    let mut cmd = Command::new("ffmpeg");
    cmd.args([
        "-hide_banner",
        "-loglevel",
        "error",
        "-re",
        "-f",
        "lavfi",
        "-i",
    ])
    .arg("testsrc=size=320x240:rate=25")
    .args([
        "-f",
        "lavfi",
        "-i",
        "sine=sample_rate=48000",
        "-t",
        "30",
        "-pix_fmt",
        "yuv420p",
    ])
    .args(["-c:v", vcodec, "-g", "25"]);
    match vcodec {
        "libx265" => {
            cmd.args(["-x265-params", "log-level=error"]);
        }
        "libvpx" | "libvpx-vp9" => {
            cmd.args(["-deadline", "realtime", "-cpu-used", "8", "-b:v", "300k"]);
        }
        "libsvtav1" => {
            cmd.args(["-preset", "12", "-svtav1-params", "lp=2"]);
        }
        _ => {}
    }
    // ffmpeg's VP9 and AV1 RTP packetizers are "experimental".
    cmd.args(["-strict", "experimental"]);
    cmd.args([
        "-c:a",
        acodec,
        "-f",
        "rtsp",
        "-rtsp_transport",
        transport,
        url,
    ])
    .stdout(Stdio::null())
    .stderr(Stdio::null());
    Kill(cmd.spawn().expect("spawn ffmpeg"))
}

fn probe(url: &str, transport: &str) -> String {
    let out = Command::new("ffprobe")
        .args([
            "-hide_banner",
            "-loglevel",
            "error",
            "-rtsp_transport",
            transport,
        ])
        .args([
            "-show_entries",
            "stream=codec_name,width,height",
            "-of",
            "compact",
            url,
        ])
        .output()
        .expect("ffprobe");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn decode(url: &str, transport: &str) -> (bool, String) {
    let out = Command::new("ffmpeg")
        .args([
            "-hide_banner",
            "-loglevel",
            "warning",
            "-rtsp_transport",
            transport,
            "-i",
            url,
        ])
        .args(["-t", "2", "-f", "null", "-"])
        .output()
        .expect("ffmpeg");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn wait_live(hub: &Hub, path: &str) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while !hub
        .stream_info(path)
        .is_some_and(|i| i.publishing && i.packets_in > 30)
    {
        assert!(Instant::now() < deadline, "{path} never went live");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn interop(pub_transport: &str, vcodec: &str, acodec: &str, vname: &str, aname: &str) {
    if !have("ffmpeg") || !have("ffprobe") {
        eprintln!("ffmpeg/ffprobe not found: skipped");
        return;
    }
    let (hub, engine, addr) = start(RtspConfig::default());
    let url = format!("rtsp://{addr}/live/ff");
    let _publisher = publish(&url, pub_transport, vcodec, acodec);
    wait_live(&hub, "live/ff");
    for t in ["tcp", "udp"] {
        let p = probe(&url, t);
        assert!(
            p.contains(&format!("codec_name={vname}|width=320|height=240")),
            "{t}: {p}"
        );
        assert!(p.contains(&format!("codec_name={aname}")), "{t}: {p}");
        let (ok, log) = decode(&url, t);
        assert!(ok, "{t}: {log}");
        assert!(!log.contains("non monotonically"), "{t}: {log}");
    }
    engine.shutdown();
}

#[test]
fn ffmpeg_h264_aac_publish_tcp_play_tcp_udp() {
    interop("tcp", "libx264", "aac", "h264", "aac");
}

#[test]
fn ffmpeg_h265_opus_publish_udp_play_tcp_udp() {
    interop("udp", "libx265", "libopus", "hevc", "opus");
}

#[test]
fn ffmpeg_vp8_opus_publish_tcp_play_tcp_udp() {
    interop("tcp", "libvpx", "libopus", "vp8", "opus");
}

#[test]
fn ffmpeg_vp9_opus_publish_udp_play_tcp_udp() {
    interop("udp", "libvpx-vp9", "libopus", "vp9", "opus");
}

#[test]
fn ffmpeg_av1_opus_publish_tcp_play_tcp_udp() {
    // ffmpeg packetizes AV1 over RTP from 7.1 on.
    if have("ffmpeg") && !have_av1_rtp() {
        eprintln!("this ffmpeg has no AV1 RTP packetizer: skipped");
        return;
    }
    interop("tcp", "libsvtav1", "libopus", "av1", "opus");
}

/// Whether ffmpeg packetizes AV1 over RTP (checked on a tiny clip; ffmpeg 6 with SVT-AV1 may
/// hang on it, so it gets 20 seconds).
fn have_av1_rtp() -> bool {
    let Ok(mut child) = Command::new("ffmpeg")
        .args([
            "-nostdin",
            "-hide_banner",
            "-loglevel",
            "error",
            "-f",
            "lavfi",
            "-i",
        ])
        .arg("testsrc=size=64x64:rate=5")
        .args(["-t", "0.2", "-c:v", "libsvtav1", "-strict", "experimental"])
        .args(["-f", "rtp", "rtp://127.0.0.1:9"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        return false;
    };
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(100)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
        }
    }
}

/// Reads until the server closes the connection; returns how long that took (`None`: still
/// open after `max`).
fn closed_within(s: &mut TcpStream, max: Duration) -> Option<Duration> {
    let t = Instant::now();
    s.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
    let mut b = vec![0u8; 65536];
    while t.elapsed() < max {
        match s.read(&mut b) {
            Ok(0) => return Some(t.elapsed()),
            Ok(_) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(_) => return Some(t.elapsed()),
        }
    }
    None
}

fn timeouts(request_ms: u64, session_ms: u64) -> RtspConfig {
    let mut cfg = RtspConfig::default();
    cfg.request_timeout = Duration::from_millis(request_ms);
    cfg.session_timeout = Duration::from_millis(session_ms);
    cfg
}

#[test]
fn timeouts_have_safe_defaults_and_the_advertised_one_is_configured() {
    let cfg = RtspConfig::default();
    assert_eq!(cfg.request_timeout, Duration::from_secs(10));
    assert_eq!(cfg.session_timeout, Duration::from_secs(60));
    let mut cfg = RtspConfig::default();
    cfg.session_timeout = Duration::from_secs(25);
    let (hub, _engine, addr) = start(cfg);
    let track = Track::video(Codec::H264, h264::Config::from_sets(SPS, PPS).encode());
    let _p = hub
        .publish("cam", Arc::from(vec![track]), PeerInfo::default())
        .unwrap();
    let mut c = Client::connect(addr);
    let (st, head, _) = c.request(
        "SETUP",
        &format!("rtsp://{addr}/cam/trackID=0"),
        "Transport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n",
        "",
    );
    assert_eq!(st, 200, "{head}");
    assert!(head.contains(";timeout=25"), "{head}");
}

/// No first request, or a request trickled a byte at a time: closed after the request timeout.
#[test]
fn request_timeout_closes_silent_and_trickling_clients() {
    let (_hub, _engine, addr) = start(timeouts(300, 10_000));
    let mut s = TcpStream::connect(addr).unwrap();
    let t = closed_within(&mut s, Duration::from_secs(3)).expect("still open");
    assert!(t >= Duration::from_millis(250), "closed too early: {t:?}");
    // A complete request first, then a second one trickled: the partial-request deadline.
    let mut c = Client::connect(addr);
    assert_eq!(c.request("OPTIONS", "*", "", "").0, 200);
    let start = Instant::now();
    let mut closed = false;
    for b in b"OPTIONS * RTSP/1.0\r\nCSeq: 9\r\nX-Pad: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
        if c.s.write_all(&[*b]).is_err()
            || closed_within(&mut c.s, Duration::from_millis(50)).is_some()
        {
            closed = true;
            break;
        }
    }
    assert!(closed, "a trickled request was kept open");
    assert!(start.elapsed() < Duration::from_secs(2));
}

/// The advertised session timeout is enforced: silent past it closes; keep-alives under it
/// (GET_PARAMETER) keep the session.
#[test]
fn session_timeout_is_enforced() {
    let (_hub, _engine, addr) = start(timeouts(5_000, 400));
    let mut c = Client::connect(addr);
    assert_eq!(c.request("OPTIONS", "*", "", "").0, 200);
    let t = closed_within(&mut c.s, Duration::from_secs(3)).expect("still open");
    assert!(t >= Duration::from_millis(300), "closed too early: {t:?}");
    let mut c = Client::connect(addr);
    for _ in 0..12 {
        assert_eq!(c.request("GET_PARAMETER", "*", "", "").0, 200);
        assert!(closed_within(&mut c.s, Duration::from_millis(100)).is_none());
    }
}

/// The H.264 + AAC sample: its tracks and packets.
fn av_sample() -> (only_media::Tracks, Vec<Packet>) {
    use only_media::flv;
    let mut dec = flv::Decoder::new();
    let (mut tracks, mut pkts) = (None, Vec::new());
    for t in flv::Demuxer::new()
        .feed(include_bytes!("../testdata/h264_aac.flv"))
        .unwrap()
    {
        for e in dec.write(t.tag_type, t.ts, &t.body) {
            match e {
                flv::Event::Tracks(t) => tracks = Some(t),
                flv::Event::Packet(p) => pkts.push(p),
                _ => {}
            }
        }
    }
    (tracks.unwrap(), pkts)
}

/// What a hub subscriber hears: (track, pts) of every packet.
#[derive(Clone, Default)]
struct Heard(Arc<std::sync::Mutex<Vec<(usize, only_media::av::Time)>>>);

impl only_media::Sink for Heard {
    fn on_tracks(&mut self, _t: &only_media::Tracks) {}
    fn on_packet(&mut self, p: &Arc<Packet>) {
        self.0.lock().unwrap().push((p.track, p.pts));
    }
    fn on_close(&mut self, _e: only_media::HubError) {}
}

/// How a test publisher sends RTP and RTCP.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Carry {
    /// Interleaved, RTCP on its own channel.
    Tcp,
    /// Interleaved, RTCP muxed on the RTP channel.
    TcpMux,
    /// UDP, RTCP from its own port to the server's RTCP port.
    Udp,
}

/// An NTP timestamp (32.32) of `t` after an arbitrary epoch.
fn ntp(t: only_media::av::Time) -> u64 {
    use only_media::av::SECOND;
    let t = t + 3_900_000_000 * SECOND;
    let secs = (t / SECOND) as u64;
    let frac = (((t % SECOND) as u128) << 32) / SECOND as u128;
    (secs << 32) | frac as u64
}

/// Records the H.264 + AAC sample into a server with `cfg` over `carry`, with sender reports
/// that put audio `skew` after video (at their first frames), sent before the media (`early`)
/// or halfway through. Every packet goes out at once, so arrival says nothing of the skew.
/// Returns how much later audio is than video at the start and at the end of what the hub's
/// subscriber heard (each against the source's own offset), and whether audio times only
/// increase.
fn record_with_reports(
    cfg: RtspConfig,
    carry: Carry,
    early: bool,
    skew: only_media::av::Time,
) -> (only_media::av::Time, only_media::av::Time, bool) {
    use only_media::{SubscribeOptions, rtp::Packetizer};
    let (hub, engine, addr) = start(cfg);
    let (tracks, pkts) = av_sample();
    let mut s = sdp::Session::new("rec");
    for (i, t) in tracks.iter().enumerate() {
        s.media
            .push(sdp::track_media(t, 96 + i as u8, &format!("streamid={i}")).unwrap());
    }
    let url = format!("rtsp://{addr}/live/sync");
    let mut c = Client::connect(addr);
    let (st, head, _) = c.request(
        "ANNOUNCE",
        &url,
        "Content-Type: application/sdp\r\n",
        &s.to_string(),
    );
    assert_eq!(st, 200, "{head}");
    // Per track: UDP sockets (RTP, RTCP) and the server's ports.
    let mut udp = Vec::new();
    for i in 0..tracks.len() {
        let transport = if carry == Carry::Udp {
            let a = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let b = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let t = format!(
                "RTP/AVP;unicast;client_port={}-{};mode=record",
                a.local_addr().unwrap().port(),
                b.local_addr().unwrap().port()
            );
            udp.push((a, b));
            t
        } else {
            format!(
                "RTP/AVP/TCP;unicast;interleaved={}-{};mode=record",
                2 * i,
                2 * i + 1
            )
        };
        let (st, head, _) = c.request(
            "SETUP",
            &format!("{url}/streamid={i}"),
            &format!("Transport: {transport}\r\n"),
            "",
        );
        assert_eq!(st, 200, "{head}");
        if carry == Carry::Udp {
            let ports = head
                .lines()
                .find_map(|l| l.split("server_port=").nth(1))
                .unwrap();
            let (r, t) = ports.split(';').next().unwrap().split_once('-').unwrap();
            let srv = |p: &str| SocketAddr::new(addr.ip(), p.trim().parse().unwrap());
            udp[i].0.connect(srv(r)).unwrap();
            udp[i].1.connect(srv(t)).unwrap();
        }
    }
    let heard = Heard::default();
    let mut opts = SubscribeOptions::new(PeerInfo::default());
    opts.wait = Some(Duration::from_secs(5));
    let _sub = hub.subscribe("live/sync", heard.clone(), opts).unwrap();
    let (st, head, _) = c.request("RECORD", &url, "Session: x\r\n", "");
    assert_eq!(st, 200, "{head}");

    let mut packers: Vec<Packetizer> = tracks
        .iter()
        .enumerate()
        .map(|(i, t)| Packetizer::new(t, 96 + i as u8))
        .collect();
    let first = |k: usize| pkts.iter().find(|p| p.track == k).unwrap().pts;
    let (v0, a0) = (first(0), first(1));
    // Video's first frame at NTP 0, audio's at `skew`.
    let srs: Vec<Vec<u8>> = [(v0, 0), (a0, skew)]
        .iter()
        .enumerate()
        .map(|(i, &(t, at))| packers[i].sender_report(ntp(at), packers[i].timestamp(t)))
        .collect();
    let mut wire = Vec::new();
    let send = |wire: &mut Vec<u8>, track: usize, rtcp: bool, data: &[u8]| match carry {
        Carry::Tcp => interleaved((2 * track + usize::from(rtcp)) as u8, data, wire),
        Carry::TcpMux => interleaved((2 * track) as u8, data, wire),
        Carry::Udp => {
            let (a, b) = &udp[track];
            (if rtcp { b } else { a }).send(data).unwrap();
            // Paced a little, so nothing is dropped on the way.
            std::thread::sleep(Duration::from_micros(200));
        }
    };
    if early {
        for (i, sr) in srs.iter().enumerate() {
            send(&mut wire, i, true, sr);
        }
    }
    let mut out = Vec::new();
    for (n, p) in pkts.iter().enumerate() {
        if !early && n == pkts.len() / 2 {
            for (i, sr) in srs.iter().enumerate().rev() {
                send(&mut wire, i, true, sr);
            }
        }
        out.clear();
        packers[p.track].packetize(p, &mut out);
        for r in &out {
            send(&mut wire, p.track, false, r);
        }
    }
    c.s.write_all(&wire).unwrap();
    let count = |k: usize| pkts.iter().filter(|p| p.track == k).count();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let g = heard.0.lock().unwrap();
        let n = |k: usize| g.iter().filter(|(t, _)| *t == k).count();
        if n(0) >= count(0) && n(1) >= count(1) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "heard {} / {} video, {} / {} audio ({carry:?})",
            n(0),
            count(0),
            n(1),
            count(1)
        );
        drop(g);
        std::thread::sleep(Duration::from_millis(10));
    }
    let g = heard.0.lock().unwrap().clone();
    engine.shutdown();
    // Each track's offset (heard - source) at its first and last packet; RTP timestamps
    // carry the source's spacing, so it only changes where a report moved the track.
    let offset = |k: usize, last: bool| {
        let mut src = pkts.iter().filter(|p| p.track == k);
        let mut got = g.iter().filter(|(t, _)| *t == k);
        if last {
            got.next_back().unwrap().1 - src.next_back().unwrap().pts
        } else {
            got.next().unwrap().1 - src.next().unwrap().pts
        }
    };
    let audio: Vec<_> = g.iter().filter(|(t, _)| *t == 1).map(|x| x.1).collect();
    (
        offset(1, false) - offset(0, false),
        offset(1, true) - offset(0, true),
        audio.windows(2).all(|w| w[1] >= w[0]),
    )
}

/// RECORD sessions line their tracks up by the publisher's RTCP sender reports, which put
/// audio 500 ms after video while the packets arrive together: over TCP (RTCP channels and
/// RTCP muxed on the RTP channels) and UDP (RTCP port), reports before the media (aligned
/// from the first packet) and halfway (later packets move, times keep increasing). Reports
/// 60 s apart are ignored, and with `rtcp_sync` off the times follow the arrival.
#[test]
fn record_sessions_follow_sender_reports() {
    let ms = |v: i64| v * MILLISECOND;
    let near = |got: only_media::av::Time, want: only_media::av::Time, what: &str| {
        assert!((got - want).abs() < ms(40), "{what}: {got} ns, want {want}");
    };
    for carry in [Carry::Tcp, Carry::TcpMux, Carry::Udp] {
        let (start, end, rising) = record_with_reports(RtspConfig::default(), carry, true, ms(500));
        near(start, ms(500), &format!("{carry:?} early, start"));
        near(end, ms(500), &format!("{carry:?} early, end"));
        assert!(rising, "{carry:?}");
    }
    for carry in [Carry::Tcp, Carry::Udp] {
        let (start, end, rising) =
            record_with_reports(RtspConfig::default(), carry, false, ms(500));
        near(start, 0, &format!("{carry:?} late, start"));
        near(end, ms(500), &format!("{carry:?} late, end"));
        assert!(rising, "{carry:?} late: audio times go back");
    }
    let (start, end, _) = record_with_reports(RtspConfig::default(), Carry::Tcp, true, ms(60_000));
    near(start, 0, "60 s apart, start");
    near(end, 0, "60 s apart, end");
    let mut off = RtspConfig::default();
    off.rtcp_sync = false;
    for carry in [Carry::Tcp, Carry::Udp] {
        let (start, end, _) = record_with_reports(off.clone(), carry, true, ms(500));
        near(start, 0, &format!("{carry:?} sync off, start"));
        near(end, 0, &format!("{carry:?} sync off, end"));
    }
}

/// A receiver report's sender SSRC and its report blocks (source, fraction lost, cumulative
/// lost, extended highest sequence number, jitter, LSR, DLSR), and the CNAME of the SDES that
/// must follow it in the compound packet.
#[allow(clippy::type_complexity)]
fn parse_rr(b: &[u8]) -> Option<(u32, Vec<(u32, u8, i32, u32, u32, u32, u32)>, String)> {
    let (mut rest, mut rr, mut cname) = (b, None, None);
    while rest.len() >= 4 {
        let len = (usize::from(u16::from_be_bytes([rest[2], rest[3]])) + 1) * 4;
        let p = rest.get(..len)?;
        let be = |i: usize| u32::from_be_bytes(p[i..i + 4].try_into().unwrap());
        match p[1] {
            201 => {
                let blocks = (0..usize::from(p[0] & 31))
                    .map(|k| {
                        let o = 8 + 24 * k;
                        let lost = (be(o + 4) << 8) as i32 >> 8;
                        (
                            be(o),
                            p[o + 4],
                            lost,
                            be(o + 8),
                            be(o + 12),
                            be(o + 16),
                            be(o + 20),
                        )
                    })
                    .collect();
                rr = Some((be(4), blocks));
            }
            202 if p[8] == 1 => {
                let n = usize::from(p[9]);
                cname = Some(String::from_utf8_lossy(&p[10..10 + n]).into_owned());
            }
            _ => {}
        }
        rest = &rest[len..];
    }
    let (ssrc, blocks) = rr?;
    Some((ssrc, blocks, cname?))
}

/// A RECORD session sends its publisher RTCP receiver reports on the track's RTCP channel
/// (TCP) or to its RTCP port (UDP): the publisher's SSRC, the packets it skipped as lost, the
/// highest sequence number (across a wrap), the last sender report's NTP middle bits with
/// the delay since, and an SDES CNAME. `receiver_report_interval` zero sends none.
#[test]
fn record_sessions_send_receiver_reports() {
    for (udp, every) in [(false, 100), (true, 100), (false, 0)] {
        let mut cfg = RtspConfig::default();
        cfg.receiver_report_interval = Duration::from_millis(every);
        let (_hub, engine, addr) = start(cfg);
        let track = Track::video(Codec::H264, h264::Config::from_sets(SPS, PPS).encode());
        let mut s = sdp::Session::new("rec");
        s.media
            .push(sdp::track_media(&track, 96, "streamid=0").unwrap());
        let url = format!("rtsp://{addr}/live/rr");
        let mut c = Client::connect(addr);
        let (st, _, _) = c.request(
            "ANNOUNCE",
            &url,
            "Content-Type: application/sdp\r\n",
            &s.to_string(),
        );
        assert_eq!(st, 200);
        let socks = udp.then(|| {
            let a = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let b = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            b.set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            (a, b)
        });
        let transport = match &socks {
            Some((a, b)) => format!(
                "RTP/AVP;unicast;client_port={}-{};mode=record",
                a.local_addr().unwrap().port(),
                b.local_addr().unwrap().port()
            ),
            None => "RTP/AVP/TCP;unicast;interleaved=0-1;mode=record".to_owned(),
        };
        let (st, head, _) = c.request(
            "SETUP",
            &format!("{url}/streamid=0"),
            &format!("Transport: {transport}\r\n"),
            "",
        );
        assert_eq!(st, 200, "{head}");
        if let Some((a, b)) = &socks {
            let ports = head
                .lines()
                .find_map(|l| l.split("server_port=").nth(1))
                .unwrap();
            let (r, t) = ports.split(';').next().unwrap().split_once('-').unwrap();
            a.connect(SocketAddr::new(addr.ip(), r.trim().parse().unwrap()))
                .unwrap();
            b.connect(SocketAddr::new(addr.ip(), t.trim().parse().unwrap()))
                .unwrap();
        }
        assert_eq!(c.request("RECORD", &url, "Session: x\r\n", "").0, 200);
        c.s.set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();

        let ssrc = 0x1234_5678u32;
        let ntp = 0xe000_0001_8000_0000u64;
        let send = |c: &mut Client, rtcp: bool, data: &[u8]| match &socks {
            Some((a, b)) => {
                (if rtcp { b } else { a }).send(data).unwrap();
            }
            None => {
                let mut w = Vec::new();
                interleaved(u8::from(rtcp), data, &mut w);
                c.s.write_all(&w).unwrap();
            }
        };
        send(
            &mut c,
            true,
            &only_media::rtp::sender_report(ssrc, ntp, 1000, 0, 0),
        );
        // 60 packets from sequence number 65510 (wrapping), every 10th one left out.
        let (first, n) = (65_510u16, 60u16);
        let mut lost = 0;
        let mut reports = Vec::new();
        let read = |c: &mut Client, reports: &mut Vec<Vec<u8>>| match &socks {
            Some((_, b)) => {
                let mut buf = [0u8; 1500];
                while let Ok(k) = b.recv(&mut buf) {
                    reports.push(buf[..k].to_vec());
                }
            }
            None => {
                let mut buf = [0u8; 4096];
                if let Ok(k) = c.s.read(&mut buf) {
                    c.buf.extend_from_slice(&buf[..k]);
                }
                while c.buf.len() >= 4 && c.buf[0] == b'$' {
                    let len = 4 + usize::from(u16::from_be_bytes([c.buf[2], c.buf[3]]));
                    if c.buf.len() < len {
                        break;
                    }
                    assert_eq!(c.buf[1], 1, "reports go on the RTCP channel");
                    reports.push(c.buf[4..len].to_vec());
                    c.buf.drain(..len);
                }
            }
        };
        for i in 0..n {
            let seq = first.wrapping_add(i);
            if i % 10 == 5 {
                lost += 1;
                continue;
            }
            let mut p = vec![0x80, 96];
            p.extend_from_slice(&seq.to_be_bytes());
            p.extend_from_slice(&(1000 + u32::from(i) * 3000).to_be_bytes());
            p.extend_from_slice(&ssrc.to_be_bytes());
            p.extend_from_slice(&[0x41, 0x9a, 0x00, 0x11, 0x22]);
            send(&mut c, false, &p);
            std::thread::sleep(Duration::from_millis(10));
            if i % 8 == 0 {
                read(&mut c, &mut reports);
            }
        }
        // One more packet after an interval: its report counts everything.
        std::thread::sleep(Duration::from_millis(every + 20));
        let last = first.wrapping_add(n);
        let mut p = vec![0x80, 96];
        p.extend_from_slice(&last.to_be_bytes());
        p.extend_from_slice(&(1000 + u32::from(n) * 3000).to_be_bytes());
        p.extend_from_slice(&ssrc.to_be_bytes());
        p.extend_from_slice(&[0x41, 0x9a, 0x00, 0x11, 0x22]);
        send(&mut c, false, &p);
        for _ in 0..5 {
            read(&mut c, &mut reports);
        }
        engine.shutdown();
        if every == 0 {
            assert!(reports.is_empty(), "reports while off: {reports:?}");
            continue;
        }
        assert!(reports.len() >= 3, "udp {udp}: {} reports", reports.len());
        let parsed: Vec<_> = reports
            .iter()
            .map(|r| parse_rr(r).unwrap_or_else(|| panic!("not an RR + SDES: {r:02x?}")))
            .collect();
        let (me, _, cname) = &parsed[0];
        assert!(cname.starts_with("only-media-"), "{cname}");
        let (_, blocks, _) = parsed.last().unwrap();
        assert_eq!(blocks.len(), 1);
        let (src, _fraction, cum, ext_max, _jitter, lsr, dlsr) = blocks[0];
        assert_eq!(src, ssrc);
        assert_eq!(cum, lost, "udp {udp}");
        assert_eq!(
            ext_max,
            (1 << 16) + u32::from(last),
            "udp {udp}: across the wrap"
        );
        assert_eq!(lsr, (ntp >> 16) as u32);
        // The report followed the sender report by the 0.7 s or so the packets took.
        let since = f64::from(dlsr) / 65536.0;
        assert!((0.5..5.0).contains(&since), "DLSR {since} s");
        // Every report comes from the same receiver SSRC, and an earlier one saw the losses
        // of its interval.
        assert!(parsed.iter().all(|(s, _, _)| s == me));
        assert!(parsed.iter().any(|(_, b, _)| b[0].1 > 0), "a fraction lost");
    }
}

/// GStreamer's `rtspclientsink` records an H.264 test pattern to our server over UDP and TCP
/// (`docker run --network host <ONLY_GST_IMAGE> gst-launch-1.0`, the image built by
/// `tools/interop/media/rtsp-redirect.sh`). Over UDP its RTP session must parse our receiver
/// reports (`got RR packet`, and a report block about its SSRC with the LSR of its last sender
/// report); over TCP the reports must reach it, though rtspclientsink drops interleaved data
/// in RECORD mode (`ignoring data message`) before its RTP session sees them. Skipped without
/// `ONLY_GST_IMAGE`.
#[test]
fn gstreamer_record_gets_receiver_reports() {
    let Ok(image) = std::env::var("ONLY_GST_IMAGE") else {
        eprintln!("ONLY_GST_IMAGE not set: skipped (see tools/interop/media/rtsp-redirect.sh)");
        return;
    };
    for proto in ["udp", "tcp"] {
        let mut cfg = RtspConfig::default();
        cfg.receiver_report_interval = Duration::from_secs(1);
        let (hub, engine, addr) = start(cfg);
        let path = format!("live/gst_{proto}");
        let child = Command::new("docker")
            .args([
                "run",
                "--rm",
                "--network",
                "host",
                "-e",
                "GST_DEBUG=*:1,rtpsession:5,rtpsource:5,rtspclientsink:5",
            ])
            .arg(&image)
            .args(["timeout", "-s", "INT", "8", "gst-launch-1.0", "-e"])
            .args([
                "videotestsrc",
                "is-live=true",
                "!",
                "video/x-raw,width=320,height=240",
            ])
            .args([
                "!",
                "x264enc",
                "tune=zerolatency",
                "key-int-max=25",
                "!",
                "h264parse",
            ])
            .args(["!", "rtspclientsink"])
            .arg(format!("location=rtsp://{addr}/{path}"))
            .arg(format!("protocols={proto}"))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("docker");
        // What the session recorded, while it lasts.
        let mut packets = 0;
        let t0 = Instant::now();
        while t0.elapsed() < Duration::from_secs(7) {
            packets = packets.max(hub.stream_info(&path).map_or(0, |i| i.packets_in));
            std::thread::sleep(Duration::from_millis(100));
        }
        let out = child.wait_with_output().expect("gst-launch");
        let log = String::from_utf8_lossy(&out.stderr);
        engine.shutdown();
        let file = std::env::temp_dir().join(format!("only-gst-{proto}.log"));
        let _ = std::fs::write(&file, [&out.stdout[..], &out.stderr[..]].concat());
        // Strip the colours of GStreamer's log.
        let plain = |l: &str| {
            let mut out = String::new();
            let mut esc = false;
            for c in l.chars() {
                match (esc, c) {
                    (false, '\u{1b}') => esc = true,
                    (true, 'm') => esc = false,
                    (true, _) => {}
                    (false, c) => out.push(c),
                }
            }
            out
        };
        let count = |what: &str| log.lines().filter(|l| l.contains(what)).count();
        assert!(
            packets > 50,
            "{proto}: {packets} packets recorded; log in {}",
            file.display()
        );
        if proto == "tcp" {
            // rtspclientsink drops interleaved data in RECORD mode ("ignoring data message"):
            // the reports reach it, its RTP session never sees them.
            let ignored = count("ignoring data message");
            assert!(
                ignored >= 3,
                "tcp: {ignored} interleaved messages; log in {}",
                file.display()
            );
            eprintln!(
                "tcp: {ignored} receiver reports reached rtspclientsink, which ignores interleaved data"
            );
            continue;
        }
        let blocks: Vec<String> = log
            .lines()
            .filter(|l| l.contains("got RB packet"))
            .map(plain)
            .collect();
        let rrs = count("got RR packet");
        assert!(
            rrs >= 3 && !blocks.is_empty(),
            "{proto}: {rrs} RR, {} RB; log in {}",
            blocks.len(),
            file.display()
        );
        // A block with a non-zero LSR: the sender report was seen.
        let lsr = blocks.iter().any(|l| !l.contains("LSR 0000:0000"));
        let last = blocks
            .last()
            .map_or("", |l| &l[l.find("got RB").unwrap_or(0)..]);
        eprintln!("{proto}: {rrs} RR from us parsed, the last {last:?}; LSR echoed: {lsr}");
        assert!(lsr, "{proto}: no LSR in {blocks:#?}");
    }
}

// ---- REDIRECT and third-party clients ------------------------------------------------------

/// A server of `cfg` and its handle.
fn start_server(cfg: RtspConfig) -> (Hub, RtspServer, Arc<Engine>, SocketAddr) {
    let hub = Hub::default();
    let srv = RtspServer::new(hub.clone(), cfg);
    srv.listen_udp("127.0.0.1:0".parse().unwrap()).unwrap();
    let engine = Arc::new(
        Engine::builder()
            .listen(Listener::tcp("127.0.0.1:0".parse().unwrap()).serve(srv.clone()))
            .build()
            .unwrap(),
    );
    engine.start().unwrap();
    let addr = engine.local_addrs()[0];
    (hub, srv, engine, addr)
}

/// The H.264 + AAC sample published at `path`, looped in real time until `stop`.
fn feed_looped(hub: &Hub, path: &str, stop: Arc<std::sync::atomic::AtomicBool>) {
    use std::sync::atomic::Ordering;
    let (tracks, pkts) = av_sample();
    let p = hub.publish(path, tracks, PeerInfo::default()).unwrap();
    std::thread::spawn(move || {
        let span = pkts.iter().map(|p| p.dts).max().unwrap_or(0) + 40 * MILLISECOND;
        let start = Instant::now();
        for round in 0i64.. {
            for pkt in &pkts {
                if stop.load(Ordering::Relaxed) {
                    p.close();
                    return;
                }
                let off = round * span;
                let at = Duration::from_nanos((pkt.dts + off).max(0) as u64);
                if let Some(d) = at.checked_sub(start.elapsed()) {
                    std::thread::sleep(d);
                }
                let mut q = pkt.clone();
                q.dts += off;
                q.pts += off;
                p.write(q);
            }
        }
    });
}

/// A TCP proxy on `port` (0: any) to `to` that keeps what clients send once `armed`.
struct Tap {
    addr: SocketAddr,
    armed: Arc<std::sync::atomic::AtomicBool>,
    seen: Arc<std::sync::Mutex<Vec<u8>>>,
}

impl Tap {
    fn new(port: u16, to: SocketAddr) -> Tap {
        use std::sync::atomic::{AtomicBool, Ordering};
        let l = std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
        let addr = l.local_addr().unwrap();
        let armed = Arc::new(AtomicBool::new(false));
        let seen: Arc<std::sync::Mutex<Vec<u8>>> = Arc::default();
        let (a2, s2) = (armed.clone(), seen.clone());
        std::thread::spawn(move || {
            for c in l.incoming() {
                let Ok(c) = c else { continue };
                let Ok(s) = TcpStream::connect(to) else {
                    continue;
                };
                let (mut c1, mut s1) = (c.try_clone().unwrap(), s.try_clone().unwrap());
                std::thread::spawn(move || {
                    let _ = std::io::copy(&mut s1, &mut c1);
                    let _ = c1.shutdown(std::net::Shutdown::Both);
                });
                let (a3, s3) = (a2.clone(), s2.clone());
                std::thread::spawn(move || {
                    let (mut c, mut s) = (c, s);
                    let mut b = vec![0u8; 65536];
                    loop {
                        let n = match c.read(&mut b) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => n,
                        };
                        if a3.load(Ordering::Relaxed) {
                            let mut g = s3.lock().unwrap();
                            if g.len() < 8 << 20 {
                                g.extend_from_slice(&b[..n]);
                            }
                        }
                        if s.write_all(&b[..n]).is_err() {
                            break;
                        }
                    }
                    let _ = s.shutdown(std::net::Shutdown::Both);
                });
            }
        });
        Tap { addr, armed, seen }
    }

    /// The status of the first response the client sent once armed, and the requests after.
    fn answer(&self) -> (Option<u16>, Vec<String>) {
        let g = self.seen.lock().unwrap();
        let text: String = g
            .iter()
            .map(|&b| {
                if b.is_ascii_graphic() || b == b' ' || b == b'\n' {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        let status = text
            .find("RTSP/1.0 ")
            .and_then(|i| text.get(i + 9..i + 12)?.parse().ok());
        let methods = text
            .lines()
            .filter_map(|l| {
                let (m, rest) = l.split_once(' ')?;
                (rest.starts_with("rtsp://")
                    && m.bytes().all(|b| b.is_ascii_uppercase() || b == b'_'))
                .then(|| m.trim_start_matches('.').to_owned())
            })
            .collect();
        (status, methods)
    }
}

/// What a third-party RTSP client does with the server's `REDIRECT`. Run by
/// `tools/interop/media/rtsp-server-redirect.sh` (skipped without `ONLY_REDIRECT_CLIENT`):
/// `ONLY_REDIRECT_CLIENT` is a shell command with `{url}`, the stream on server A through a
/// proxy that sees the client's answer; `ONLY_REDIRECT_MODE` `play` (default: the client
/// plays `src`) or `record` (it records to `pushed`); `ONLY_REDIRECT_PORT` the proxy's port;
/// `ONLY_REDIRECT_STOP` a command run at the end; `ONLY_REDIRECT_FOLLOWS=1` asserts the client
/// moves to server B. Server A redirects the path to B with a 4 s grace and must have ended
/// the session (closed the connection) once the grace passed, whatever the client does.
#[test]
fn third_party_redirect() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let Ok(cmd) = std::env::var("ONLY_REDIRECT_CLIENT") else {
        eprintln!(
            "ONLY_REDIRECT_CLIENT not set: skipped (see tools/interop/media/rtsp-server-redirect.sh)"
        );
        return;
    };
    let record = std::env::var("ONLY_REDIRECT_MODE").is_ok_and(|m| m == "record");
    let port = std::env::var("ONLY_REDIRECT_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(0);
    let (hub_a, srv_a, e_a, a) = start_server(RtspConfig::default());
    let (hub_b, srv_b, e_b, b) = start_server(RtspConfig::default());
    let stop = Arc::new(AtomicBool::new(false));
    feed_looped(&hub_a, "src", stop.clone());
    feed_looped(&hub_b, "src", stop.clone());
    let tap = Tap::new(port, a);
    let path = if record { "pushed" } else { "src" };
    let url = format!("rtsp://{}/{path}", tap.addr);
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(cmd.replace("{url}", &url))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(40);
    let live = || {
        let s = srv_a.sessions();
        let flowing = !record
            || hub_a
                .stream_info("pushed")
                .is_some_and(|i| i.publishing && i.packets_in > 50);
        s.iter().any(|s| s.path == path && s.recording == record) && flowing
    };
    while !live() {
        assert!(Instant::now() < deadline, "the client never set {path} up");
        std::thread::sleep(Duration::from_millis(50));
    }
    std::thread::sleep(Duration::from_secs(2));
    tap.armed.store(true, Ordering::Relaxed);
    let grace = Duration::from_secs(4);
    let sent = srv_a.redirect_path(
        path,
        &only_media::rtsp::Redirect::new(format!("rtsp://{b}/{path}")).grace(grace),
    );
    assert_eq!(sent, 1);
    let t0 = Instant::now();
    let (mut gone, mut followed) = (None, false);
    while t0.elapsed() < grace + Duration::from_secs(3) {
        if gone.is_none() && srv_a.sessions().is_empty() {
            gone = Some(t0.elapsed());
        }
        followed |= srv_b.sessions().iter().any(|s| s.path == path)
            && (!record
                || hub_b
                    .stream_info("pushed")
                    .is_some_and(|i| i.publishing && i.packets_in > 20));
        if gone.is_some() && followed {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let (status, after) = tap.answer();
    println!(
        "REDIRECT-RESULT mode={} answer={} requests-after={after:?} followed={followed} session-ended-after={}",
        if record { "record" } else { "play" },
        status.map_or_else(|| "none".to_owned(), |s| s.to_string()),
        gone.map_or_else(|| "never".to_owned(), |d| format!("{} ms", d.as_millis())),
    );
    let _ = child.kill();
    let _ = child.wait();
    if let Ok(stop_cmd) = std::env::var("ONLY_REDIRECT_STOP") {
        let _ = Command::new("sh").arg("-c").arg(stop_cmd).status();
    }
    stop.store(true, Ordering::Relaxed);
    assert!(
        gone.is_some_and(|d| d <= grace + Duration::from_secs(2)),
        "the session was not ended"
    );
    if std::env::var("ONLY_REDIRECT_FOLLOWS").is_ok_and(|v| v == "1") {
        assert!(followed, "the client did not move to server B");
    }
    e_a.shutdown();
    e_b.shutdown();
}
