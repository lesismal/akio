//! HTTP playback tests: HTTP-FLV, WS-FLV and HLS (plain and Low-Latency) of a hub stream, read
//! with hand-written clients, and ffmpeg publishing over RTMP with ffprobe / ffmpeg playing the
//! HTTP outputs (skipped when they are not installed).

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    process::{Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};

use only::{Engine, Listener};
use only_http::{Router, serve};
use only_media::{
    Codec, Hub, Packet, PeerInfo, Tracks,
    flv::{Decoder, Demuxer, Event},
    hls::{Hls, HlsConfig},
    http::MediaHttp,
    httpflv::{HttpFlv, HttpFlvConfig},
    mpegts,
    rtmp::{RtmpConfig, RtmpServer},
};

const SAMPLE: &[u8] = include_bytes!("../testdata/h264_aac.flv");

fn sample() -> (Tracks, Vec<Packet>) {
    let mut dec = Decoder::new();
    let mut tracks = None;
    let mut pkts = Vec::new();
    for t in Demuxer::new().feed(SAMPLE).unwrap() {
        for e in dec.write(t.tag_type, t.ts, &t.body) {
            match e {
                Event::Tracks(t) => tracks = Some(t),
                Event::Packet(p) => pkts.push(p),
                _ => {}
            }
        }
    }
    (tracks.unwrap(), pkts)
}

struct Server {
    hub: Hub,
    engine: Arc<Engine>,
    http: SocketAddr,
    rtmp: SocketAddr,
}

fn start(hls: HlsConfig) -> Server {
    let hub = Hub::default();
    let mut fcfg = HttpFlvConfig::default();
    fcfg.play_wait = Some(Duration::from_secs(5));
    let media = MediaHttp::new()
        .flv(HttpFlv::new(hub.clone(), fcfg))
        .hls(Hls::new(hub.clone(), hls));
    let app = Router::new().get("/*path", media);
    let engine = Arc::new(
        Engine::builder()
            .listen(Listener::tcp("127.0.0.1:0".parse().unwrap()).serve(serve(app)))
            .listen(
                Listener::tcp("127.0.0.1:0".parse().unwrap())
                    .serve(RtmpServer::new(hub.clone(), RtmpConfig::default())),
            )
            .build()
            .unwrap(),
    );
    engine.start().unwrap();
    let a = engine.local_addrs();
    Server {
        hub,
        engine,
        http: a[0],
        rtmp: a[1],
    }
}

/// GET returning (status, head, body) for a complete (Content-Length) response.
fn get(addr: SocketAddr, path: &str) -> (u16, String, Vec<u8>) {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut all = Vec::new();
    let _ = s.read_to_end(&mut all);
    let end = all.windows(4).position(|w| w == b"\r\n\r\n").expect("head");
    let head = String::from_utf8_lossy(&all[..end]).into_owned();
    let status = head[9..12].parse().unwrap();
    (status, head, all[end + 4..].to_vec())
}

fn hls_segments(playlist: &str, prefix: &str) -> Vec<String> {
    playlist
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .map(|l| format!("{prefix}/{l}"))
        .collect()
}

fn demux_ts(data: &[u8]) -> (Option<Tracks>, Vec<Packet>) {
    let mut d = mpegts::demux::Demuxer::new();
    let mut tracks = None;
    let mut pkts = Vec::new();
    let mut emit = |e| match e {
        mpegts::demux::Event::Tracks(t) => tracks = Some(t),
        mpegts::demux::Event::Packet(p) => pkts.push(p),
        _ => {}
    };
    d.feed(data, &mut emit).unwrap();
    d.flush(&mut emit);
    (tracks, pkts)
}

#[test]
fn hls_of_a_hub_stream() {
    let mut cfg = HlsConfig::default();
    cfg.target_duration = Duration::from_millis(500);
    cfg.part_duration = Some(Duration::from_millis(200));
    cfg.play_wait = Some(Duration::from_secs(5));
    let srv = start(cfg);
    let (tracks, pkts) = sample();
    let hub = srv.hub.clone();
    // The first playlist request waits for the publisher and for the first segment.
    let publisher = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        let p = hub.publish("live/s", tracks, PeerInfo::default()).unwrap();
        // The sample twice in a row: four keyframes, a second apart.
        for round in 0..2 {
            for pkt in &pkts {
                let mut q = pkt.clone();
                q.dts += round * 2 * only_media::av::SECOND;
                q.pts += round * 2 * only_media::av::SECOND;
                p.write(q);
            }
        }
        // Keep the stream up while the client reads.
        std::thread::sleep(Duration::from_secs(2));
    });
    let (status, head, _) = get(srv.http, "/live/s/index.m3u8");
    assert_eq!(status, 200, "{head}");
    // Block until segment 2 is out.
    let (status, head, body) = get(srv.http, "/live/s/index.m3u8?_HLS_msn=2");
    assert_eq!(status, 200, "{head}");
    assert!(head.contains("application/vnd.apple.mpegurl"));
    let pl = String::from_utf8(body).unwrap();
    assert!(pl.starts_with("#EXTM3U"), "{pl}");
    assert!(pl.contains("#EXT-X-PART-INF:PART-TARGET=0.200"), "{pl}");
    assert!(pl.contains("#EXT-X-PRELOAD-HINT"), "{pl}");
    let segs = hls_segments(&pl, "/live/s");
    assert!(segs.len() >= 2, "{pl}");
    // Every segment is a valid transport stream starting with a keyframe.
    let mut video = 0;
    for s in &segs {
        let (status, _, ts) = get(srv.http, s);
        assert_eq!(status, 200);
        let (t, p) = demux_ts(&ts);
        let t = t.expect("tracks");
        assert_eq!(t[0].codec, Codec::H264);
        let first_video = p.iter().find(|p| p.track == 0).unwrap();
        assert!(first_video.keyframe);
        video += p.iter().filter(|p| p.track == 0).count();
    }
    assert!(video >= 25, "{video}");
    // A blocking reload for a segment already out answers at once; a part works too.
    let (status, _, _) = get(srv.http, "/live/s/index.m3u8?_HLS_msn=0&_HLS_part=0");
    assert_eq!(status, 200);
    let part = pl
        .lines()
        .find_map(|l| l.split("URI=\"").nth(1))
        .unwrap()
        .trim_end_matches(|c| c != 's')
        .trim_end_matches('"');
    let (status, _, _) = get(srv.http, &format!("/live/s/{part}"));
    assert_eq!(status, 200, "{part}");
    assert_eq!(get(srv.http, "/live/s/seg-999.ts").0, 404);
    assert_eq!(get(srv.http, "/nope/index.m3u8x").0, 404);
    publisher.join().unwrap();
    srv.engine.shutdown();
}

/// Reads a chunked HTTP-FLV response until `want` video packets were decoded.
fn read_http_flv(addr: SocketAddr, path: &str, want: usize) -> (Tracks, usize) {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    write!(s, "GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    let mut raw = Vec::new();
    let mut buf = vec![0u8; 65536];
    let mut head_done = false;
    let mut demux = Demuxer::new();
    let mut dec = Decoder::new();
    let mut tracks = None;
    let mut video = 0;
    while video < want {
        let n = s.read(&mut buf).unwrap();
        assert!(n > 0, "closed after {video} video packets");
        raw.extend_from_slice(&buf[..n]);
        if !head_done {
            let Some(end) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
                continue;
            };
            let head = String::from_utf8_lossy(&raw[..end]).into_owned();
            assert!(head.starts_with("HTTP/1.1 200"), "{head}");
            assert!(head.contains("video/x-flv"));
            raw.drain(..end + 4);
            head_done = true;
        }
        // De-chunk what is complete.
        while let Some(e) = raw.windows(2).position(|w| w == b"\r\n") {
            let n = usize::from_str_radix(std::str::from_utf8(&raw[..e]).unwrap(), 16).unwrap();
            if raw.len() < e + 2 + n + 2 {
                break;
            }
            let chunk: Vec<u8> = raw[e + 2..e + 2 + n].to_vec();
            raw.drain(..e + 2 + n + 2);
            for t in demux.feed(&chunk).unwrap() {
                for ev in dec.write(t.tag_type, t.ts, &t.body) {
                    match ev {
                        Event::Tracks(t) => tracks = Some(t),
                        Event::Packet(p) if p.track == 0 => video += 1,
                        _ => {}
                    }
                }
            }
        }
    }
    (tracks.unwrap(), video)
}

#[test]
fn http_flv_and_ws_flv_of_a_hub_stream() {
    let srv = start(HlsConfig::default());
    let (tracks, pkts) = sample();
    let p = srv
        .hub
        .publish("live/s", tracks, PeerInfo::default())
        .unwrap();
    // The first GOP is cached before the player arrives.
    let (first, rest) = pkts.split_at(
        pkts.iter()
            .position(|p| p.dts >= only_media::av::SECOND)
            .unwrap(),
    );
    for pkt in first {
        p.write(pkt.clone());
    }
    let addr = srv.http;
    let reader = std::thread::spawn(move || read_http_flv(addr, "/live/s.flv", 50));
    let ws = std::thread::spawn(move || read_ws_flv(addr, "/live/s.flv", 50));
    std::thread::sleep(Duration::from_millis(300));
    for pkt in rest {
        p.write(pkt.clone());
    }
    let (t, video) = reader.join().unwrap();
    assert_eq!(t[0].codec, Codec::H264);
    assert_eq!((t[0].width, t[0].height), (320, 240));
    assert_eq!(t[1].codec, Codec::Aac);
    assert_eq!(video, 50);
    let (t, video) = ws.join().unwrap();
    assert_eq!(t.len(), 2);
    assert_eq!(video, 50);
    drop(p);
    srv.engine.shutdown();
}

/// Reads WS-FLV: every binary message is a piece of the FLV stream.
fn read_ws_flv(addr: SocketAddr, path: &str, want: usize) -> (Tracks, usize) {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    )
    .unwrap();
    let mut raw = Vec::new();
    let mut buf = vec![0u8; 65536];
    let mut head_done = false;
    let mut demux = Demuxer::new();
    let mut dec = Decoder::new();
    let mut tracks = None;
    let mut video = 0;
    while video < want {
        let n = s.read(&mut buf).unwrap();
        assert!(n > 0);
        raw.extend_from_slice(&buf[..n]);
        if !head_done {
            let Some(end) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
                continue;
            };
            assert!(raw.starts_with(b"HTTP/1.1 101"));
            raw.drain(..end + 4);
            head_done = true;
        }
        loop {
            if raw.len() < 2 {
                break;
            }
            let (len, hl) = match raw[1] & 0x7f {
                126 if raw.len() >= 4 => (usize::from(u16::from_be_bytes([raw[2], raw[3]])), 4),
                127 if raw.len() >= 10 => {
                    let mut a = [0u8; 8];
                    a.copy_from_slice(&raw[2..10]);
                    (u64::from_be_bytes(a) as usize, 10)
                }
                126 | 127 => break,
                n => (usize::from(n), 2),
            };
            if raw.len() < hl + len {
                break;
            }
            assert_eq!(raw[0] & 0x0f, 2, "binary messages");
            let payload: Vec<u8> = raw[hl..hl + len].to_vec();
            raw.drain(..hl + len);
            for t in demux.feed(&payload).unwrap() {
                for ev in dec.write(t.tag_type, t.ts, &t.body) {
                    match ev {
                        Event::Tracks(t) => tracks = Some(t),
                        Event::Packet(p) if p.track == 0 => video += 1,
                        _ => {}
                    }
                }
            }
        }
    }
    (tracks.unwrap(), video)
}

fn have(tool: &str) -> bool {
    Command::new(tool)
        .arg("-version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn ffprobe(url: &str) -> String {
    let out = Command::new("ffprobe")
        .args([
            "-v",
            "error",
            "-show_entries",
            "stream=codec_name,width,height",
            "-of",
            "csv=p=0",
            url,
        ])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// ffmpeg publishes over RTMP; ffprobe reads HTTP-FLV, HLS and LL-HLS; ffmpeg decodes them.
#[test]
fn ffmpeg_rtmp_to_http_flv_and_hls() {
    if !have("ffmpeg") || !have("ffprobe") {
        eprintln!("ffmpeg/ffprobe not found: skipped");
        return;
    }
    let mut cfg = HlsConfig::default();
    cfg.target_duration = Duration::from_secs(1);
    cfg.part_duration = Some(Duration::from_millis(250));
    let srv = start(cfg);
    for (vcodec, want) in [("libx264", "h264,320,240"), ("libx265", "hevc,320,240")] {
        let mut pubp = Command::new("ffmpeg")
            .args([
                "-v",
                "error",
                "-re",
                "-f",
                "lavfi",
                "-i",
                "testsrc=size=320x240:rate=25",
                "-f",
                "lavfi",
                "-i",
                "sine=sample_rate=44100",
            ])
            .args([
                "-t", "12", "-pix_fmt", "yuv420p", "-c:v", vcodec, "-g", "25", "-c:a", "aac",
            ])
            .args(if vcodec == "libx265" {
                vec!["-x265-params", "log-level=error"]
            } else {
                vec![]
            })
            .args(["-f", "flv", &format!("rtmp://{}/live/ff", srv.rtmp)])
            .stdin(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while srv.hub.stream_info("live/ff").is_none_or(|s| !s.publishing) {
            assert!(Instant::now() < deadline, "ffmpeg never went live");
            std::thread::sleep(Duration::from_millis(20));
        }
        let flv_url = format!("http://{}/live/ff.flv", srv.http);
        let hls_url = format!("http://{}/live/ff/index.m3u8", srv.http);
        for url in [&flv_url, &hls_url] {
            let probe = ffprobe(url);
            assert!(
                probe.contains(want) && probe.contains("aac"),
                "{url}: {probe:?}"
            );
            let out = Command::new("ffmpeg")
                .args(["-v", "warning", "-i", url, "-t", "3", "-f", "null", "-"])
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{url}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            let err = String::from_utf8_lossy(&out.stderr);
            assert!(!err.contains("non monoton"), "{url}: {err}");
        }
        let _ = pubp.kill();
        let _ = pubp.wait();
        let deadline = Instant::now() + Duration::from_secs(10);
        while srv.hub.stream_info("live/ff").is_some_and(|s| s.publishing) {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    srv.engine.shutdown();
}
