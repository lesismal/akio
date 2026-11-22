//! fMP4 (CMAF) HLS of hub streams read by ffmpeg / ffprobe: H.264 + AAC, H.265 + AAC,
//! H.265 + Opus, VP9 + Opus and AV1 + Opus, plain and Low-Latency (parts). Each sample file is published in real time;
//! ffprobe must see the codecs on the live playlist, ffmpeg must decode it without errors,
//! and every segment (init + segment as one file) must decode, start with a keyframe and hold
//! a plausible number of frames. Without ffmpeg / ffprobe the ffmpeg parts are skipped; the
//! HTTP shape checks (names, content types, 404s) always run.

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    process::{Command, Stdio},
    sync::Arc,
    thread::JoinHandle,
    time::{Duration, Instant},
};

use akio::{Engine, Listener};
use akio_http::{Router, serve};
use akio_media::{
    Hub, Packet, PeerInfo, Tracks,
    av::{MILLISECOND, SECOND, Time},
    flv,
    hls::{Hls, HlsConfig, SegmentFormat},
    http::MediaHttp,
    mpegts,
};

fn flv_sample(data: &[u8]) -> (Tracks, Vec<Packet>) {
    let mut dec = flv::Decoder::new();
    let (mut tracks, mut pkts) = (None, Vec::new());
    for t in flv::Demuxer::new().feed(data).unwrap() {
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

fn ts_sample(data: &[u8]) -> (Tracks, Vec<Packet>) {
    let mut d = mpegts::demux::Demuxer::new();
    let (mut tracks, mut pkts) = (None, Vec::new());
    let mut emit = |e| match e {
        mpegts::demux::Event::Tracks(t) => tracks = Some(t),
        mpegts::demux::Event::Packet(p) => pkts.push(p),
        _ => {}
    };
    d.feed(data, &mut emit).unwrap();
    d.flush(&mut emit);
    (tracks.unwrap(), pkts)
}

struct Server {
    hub: Hub,
    engine: Arc<Engine>,
    http: SocketAddr,
}

fn start(hls: HlsConfig) -> Server {
    let hub = Hub::default();
    let media = MediaHttp::new().hls(Hls::new(hub.clone(), hls));
    let app = Router::new().get("/*path", media);
    let engine = Arc::new(
        Engine::builder()
            .listen(Listener::tcp("127.0.0.1:0".parse().unwrap()).serve(serve(app)))
            .build()
            .unwrap(),
    );
    engine.start().unwrap();
    let http = engine.local_addrs()[0];
    Server { hub, engine, http }
}

/// Publishes the sample `rounds` times in a row, in real time, on `path`.
fn publish(
    hub: &Hub,
    path: &str,
    (tracks, pkts): (Tracks, Vec<Packet>),
    rounds: i64,
) -> JoinHandle<()> {
    let hub = hub.clone();
    let path = path.to_owned();
    std::thread::spawn(move || {
        let first = pkts.iter().map(|p| p.dts).min().unwrap();
        let last = pkts.iter().map(|p| p.dts).max().unwrap();
        let span = last - first + 40 * MILLISECOND;
        let p = hub.publish(&path, tracks, PeerInfo::default()).unwrap();
        let t0 = Instant::now();
        for round in 0..rounds {
            for pkt in &pkts {
                let at = pkt.dts - first + round * span;
                let wait = Duration::from_nanos(at.max(0) as u64).saturating_sub(t0.elapsed());
                std::thread::sleep(wait);
                let mut q = pkt.clone();
                q.dts += round * span;
                q.pts += round * span;
                p.write(q);
            }
        }
    })
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

fn have(tool: &str) -> bool {
    Command::new(tool)
        .arg("-version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn cfg(parts: bool) -> HlsConfig {
    let mut c = HlsConfig::default();
    c.format = SegmentFormat::Fmp4;
    c.target_duration = Duration::from_secs(1);
    c.part_duration = parts.then(|| Duration::from_millis(250));
    c.play_wait = Some(Duration::from_secs(5));
    c
}

/// The URIs of a playlist: (init segments, media segments, parts).
fn uris(pl: &str) -> (Vec<String>, Vec<String>, Vec<String>) {
    let quoted = |l: &str| {
        l.split("URI=\"")
            .nth(1)
            .map(|r| r.split('"').next().unwrap().to_owned())
    };
    let maps = pl
        .lines()
        .filter(|l| l.starts_with("#EXT-X-MAP:"))
        .filter_map(quoted)
        .collect();
    let parts = pl
        .lines()
        .filter(|l| l.starts_with("#EXT-X-PART:"))
        .filter_map(quoted)
        .collect();
    let segs = pl
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .map(str::to_owned)
        .collect();
    (maps, segs, parts)
}

/// ffprobe `entries` of a file or URL as CSV lines.
fn probe(args: &[&str], input: &str) -> String {
    let out = Command::new("ffprobe")
        .args(["-v", "error"])
        .args(args)
        .args(["-of", "csv=p=0", input])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{input}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Decodes `input` with ffmpeg logging at `level`; returns what it logged (empty when clean).
fn decode(level: &str, input: &str, extra: &[&str]) -> String {
    let out = Command::new("ffmpeg")
        .args(["-nostdin", "-v", level, "-i", input])
        .args(extra)
        .args(["-f", "null", "-"])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(out.status.success(), "{input}: {err}");
    err
}

/// Serves one sample as fMP4 HLS and checks it: the playlist shape, the HTTP names, and
/// (with ffmpeg) the codecs, decoding and the segments' frames.
fn check(sample: (Tracks, Vec<Packet>), parts: bool, want: &[&str], ff: bool) {
    let srv = start(cfg(parts));
    let path = "live/f";
    let video_frames = sample.1.iter().filter(|p| p.track == 0).count();
    let sample_span: Time = {
        let d: Vec<Time> = sample.1.iter().map(|p| p.dts).collect();
        d.iter().max().unwrap() - d.iter().min().unwrap()
    };
    let publisher = publish(&srv.hub, path, sample, 5);
    // The first request waits for the publisher and the first segment.
    let (status, head, _) = get(srv.http, &format!("/{path}/index.m3u8"));
    assert_eq!(status, 200, "{head}");
    // Let a few segments be cut.
    std::thread::sleep(Duration::from_secs(4));
    let (status, head, body) = get(srv.http, &format!("/{path}/index.m3u8"));
    assert_eq!(status, 200, "{head}");
    let pl = String::from_utf8(body).unwrap();
    let version = if parts { 9 } else { 7 };
    assert!(pl.contains(&format!("#EXT-X-VERSION:{version}\n")), "{pl}");
    let (maps, segs, part_uris) = uris(&pl);
    assert_eq!(maps, ["init-0.mp4"], "{pl}");
    assert!(segs.len() >= 2, "{pl}");
    assert!(
        segs.iter()
            .all(|s| s.starts_with("seg-") && s.ends_with(".m4s")),
        "{pl}"
    );
    assert_eq!(parts, !part_uris.is_empty(), "{pl}");
    assert!(
        part_uris
            .iter()
            .all(|p| p.starts_with("part-") && p.ends_with(".m4s"))
    );

    // HTTP: content types; the other format's names and unknown inits are 404.
    let (status, head, init) = get(srv.http, &format!("/{path}/init-0.mp4"));
    assert_eq!(status, 200);
    assert!(head.contains("video/mp4"), "{head}");
    let (status, head, _) = get(srv.http, &format!("/{path}/{}", segs[0]));
    assert_eq!(status, 200);
    assert!(head.contains("video/iso.segment"), "{head}");
    if let Some(p) = part_uris.first() {
        let (status, head, _) = get(srv.http, &format!("/{path}/{p}"));
        assert_eq!(status, 200, "{p}");
        assert!(head.contains("video/iso.segment"), "{head}");
    }
    let n = segs[0].trim_start_matches("seg-").trim_end_matches(".m4s");
    assert_eq!(get(srv.http, &format!("/{path}/seg-{n}.ts")).0, 404);
    assert_eq!(get(srv.http, &format!("/{path}/part-{n}.0.ts")).0, 404);
    assert_eq!(get(srv.http, &format!("/{path}/init-9.mp4")).0, 404);
    assert_eq!(get(srv.http, &format!("/{path}/init-x.mp4")).0, 404);

    if ff {
        let url = format!("http://{}/{path}/index.m3u8", srv.http);
        let streams = probe(&["-show_entries", "stream=codec_name"], &url);
        for w in want {
            assert!(
                streams.lines().any(|l| l.trim() == *w),
                "{url}: {streams:?} lacks {w}"
            );
        }
        let err = decode("error", &url, &["-t", "3"]);
        assert!(err.trim().is_empty(), "{url}: {err}");

        // Each segment on its own (init + segment): decodes cleanly, starts with a
        // keyframe, frames and duration in line with the sample's frame rate.
        let dir = env!("CARGO_TARGET_TMPDIR");
        for (i, s) in segs.iter().enumerate() {
            let (status, _, data) = get(srv.http, &format!("/{path}/{s}"));
            assert_eq!(status, 200, "{s}");
            let file = format!("{dir}/fmp4-{}-{}-{i}.mp4", want.join("-"), u8::from(parts));
            let mut all = init.clone();
            all.extend_from_slice(&data);
            std::fs::write(&file, &all).unwrap();
            let err = decode("warning", &file, &[]);
            assert!(err.trim().is_empty(), "{s}: {err}");
            let pkts = probe(
                &[
                    "-select_streams",
                    "v:0",
                    "-show_entries",
                    "packet=flags,duration_time",
                ],
                &file,
            );
            let lines: Vec<&str> = pkts.lines().filter(|l| !l.is_empty()).collect();
            assert!(!lines.is_empty(), "{s}: no video packets");
            assert!(lines[0].contains('K'), "{s}: first packet {}", lines[0]);
            // A segment is about a target duration: between 0.5 and 3 s of frames at the
            // sample's rate.
            let fps = video_frames as f64 / (sample_span as f64 / SECOND as f64);
            let n = lines.len() as f64;
            assert!(
                n >= 0.5 * fps && n <= 3.0 * fps,
                "{s}: {n} frames at {fps:.1} fps"
            );
            let durs: Vec<f64> = lines
                .iter()
                .filter_map(|l| l.split(',').find_map(|f| f.parse::<f64>().ok()))
                .collect();
            // ffprobe reports no packet durations for fragmented VP9 (ffmpeg's own output
            // included): the check needs them all.
            if durs.len() == lines.len() {
                let dur: f64 = durs.iter().sum();
                assert!(
                    (dur - n / fps).abs() < 0.2,
                    "{s}: {dur:.3} s for {n} frames"
                );
            }
            let audio = probe(
                &["-select_streams", "a:0", "-show_entries", "packet=pts_time"],
                &file,
            );
            assert!(audio.lines().count() > 10, "{s}: audio packets {audio:?}");
            let _ = std::fs::remove_file(&file);
        }
    }
    publisher.join().unwrap();
    srv.engine.shutdown();
}

fn ffmpeg_present() -> bool {
    let ok = have("ffmpeg") && have("ffprobe");
    if !ok {
        eprintln!("ffmpeg/ffprobe not found: ffmpeg checks skipped");
    }
    ok
}

#[test]
fn fmp4_hls_h264_aac() {
    let ff = ffmpeg_present();
    let s = || flv_sample(include_bytes!("../testdata/h264_aac.flv"));
    check(s(), false, &["h264", "aac"], ff);
    check(s(), true, &["h264", "aac"], ff);
}

#[test]
fn fmp4_hls_h265_aac() {
    let ff = ffmpeg_present();
    let s = || flv_sample(include_bytes!("../testdata/h265_aac.flv"));
    check(s(), false, &["hevc", "aac"], ff);
    check(s(), true, &["hevc", "aac"], ff);
}

#[test]
fn fmp4_hls_h265_opus() {
    let ff = ffmpeg_present();
    let s = || ts_sample(include_bytes!("../testdata/h265_opus.ts"));
    check(s(), false, &["hevc", "opus"], ff);
    check(s(), true, &["hevc", "opus"], ff);
}

#[test]
fn fmp4_hls_vp9_opus() {
    let ff = ffmpeg_present();
    let s = || flv_sample(include_bytes!("../testdata/vp9_opus.flv"));
    check(s(), false, &["vp9", "opus"], ff);
    check(s(), true, &["vp9", "opus"], ff);
}

#[test]
fn fmp4_hls_av1_opus() {
    let ff = ffmpeg_present();
    let s = || flv_sample(include_bytes!("../testdata/av1_opus.flv"));
    check(s(), false, &["av1", "opus"], ff);
    check(s(), true, &["av1", "opus"], ff);
}
