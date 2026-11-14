//! RTSP server tests: a hand-written client against hub-published packets, and ffmpeg /
//! ffprobe as publisher and player (skipped when they are not installed).

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
    if vcodec == "libx265" {
        cmd.args(["-x265-params", "log-level=error"]);
    }
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
