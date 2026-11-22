//! Multivariant HLS over HTTP: three renditions published as separate hub streams (H.264 +
//! AAC, H.265 + AAC, and an audio-only AAC rendition in an audio group) tied together by
//! `Hls::add_multivariant`, in MPEG-TS and in fMP4 with LL-HLS parts. The multivariant
//! playlist must list them with BANDWIDTH, CODECS, RESOLUTION and AUDIO, its URIs must lead
//! to the media playlists, and ffprobe / ffmpeg (skipped when not installed) must read every
//! variant through it.

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

use akio::{Engine, Listener};
use akio_http::{Router, serve};
use akio_media::{
    Hub, Packet, PeerInfo, Tracks,
    av::MILLISECOND,
    flv,
    hls::{AudioRendition, Hls, HlsConfig, Multivariant, SegmentFormat, Variant},
    http::MediaHttp,
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

/// The audio track of a sample on its own.
fn audio_only((tracks, pkts): (Tracks, Vec<Packet>)) -> (Tracks, Vec<Packet>) {
    let a = tracks.iter().position(|t| t.codec.is_audio()).unwrap();
    let t: Tracks = Arc::from(vec![tracks[a].clone()]);
    let p = pkts
        .into_iter()
        .filter(|p| p.track == a)
        .map(|mut p| {
            p.track = 0;
            p
        })
        .collect();
    (t, p)
}

/// Publishes the sample in a loop, in real time, on `path` until `stop`.
fn publish(
    hub: &Hub,
    path: &str,
    (tracks, pkts): (Tracks, Vec<Packet>),
    stop: Arc<AtomicBool>,
) -> JoinHandle<()> {
    let hub = hub.clone();
    let path = path.to_owned();
    std::thread::spawn(move || {
        let first = pkts.iter().map(|p| p.dts).min().unwrap();
        let last = pkts.iter().map(|p| p.dts).max().unwrap();
        let span = last - first + 40 * MILLISECOND;
        let p = hub.publish(&path, tracks, PeerInfo::default()).unwrap();
        let t0 = Instant::now();
        let mut round = 0;
        while !stop.load(Ordering::Acquire) {
            for pkt in &pkts {
                let at = pkt.dts - first + round * span;
                let wait = Duration::from_nanos(at.max(0) as u64).saturating_sub(t0.elapsed());
                std::thread::sleep(wait);
                let mut q = pkt.clone();
                q.dts += round * span;
                q.pts += round * span;
                p.write(q);
            }
            round += 1;
        }
    })
}

fn get(addr: SocketAddr, path: &str) -> (u16, String, Vec<u8>) {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
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

fn check(format: SegmentFormat, parts: bool) {
    let hub = Hub::default();
    let mut cfg = HlsConfig::default();
    cfg.format = format;
    cfg.target_duration = Duration::from_secs(1);
    cfg.part_duration = parts.then(|| Duration::from_millis(250));
    cfg.play_wait = Some(Duration::from_secs(5));
    let hls = Hls::new(hub.clone(), cfg);
    let mut m = Multivariant::new();
    for (path, bw) in [("live/cam_hevc", None), ("live/cam_avc", Some(400_000))] {
        let mut v = Variant::new(path);
        v.bandwidth = bw;
        v.audio_group = Some("aac".into());
        m.variants.push(v);
    }
    let mut en = AudioRendition::new("aac", "Main", "live/cam_audio");
    en.default = true;
    en.language = Some("en".into());
    m.audio.push(en);
    hls.add_multivariant("live/cam", m);
    let app = Router::new().get("/*path", MediaHttp::new().hls(hls.clone()));
    let engine = Arc::new(
        Engine::builder()
            .listen(Listener::tcp("127.0.0.1:0".parse().unwrap()).serve(serve(app)))
            .build()
            .unwrap(),
    );
    engine.start().unwrap();
    let addr = engine.local_addrs()[0];
    let stop = Arc::new(AtomicBool::new(false));
    let avc = || flv_sample(include_bytes!("../testdata/h264_aac.flv"));
    let hevc = flv_sample(include_bytes!("../testdata/h265_aac.flv"));
    let publishers = vec![
        publish(&hub, "live/cam_avc", avc(), stop.clone()),
        publish(&hub, "live/cam_hevc", hevc, stop.clone()),
        publish(&hub, "live/cam_audio", audio_only(avc()), stop.clone()),
    ];
    // The first request waits for every rendition's first segment.
    let t0 = Instant::now();
    let (status, head, body) = get(addr, "/live/cam.m3u8?k=v");
    assert_eq!(status, 200, "{head}");
    assert!(t0.elapsed() < Duration::from_secs(10));
    assert!(head.contains("application/vnd.apple.mpegurl"), "{head}");
    let pl = String::from_utf8(body).unwrap();
    let fmp4 = format == SegmentFormat::Fmp4;
    let ver = if fmp4 { 7 } else { 3 };
    assert!(pl.contains(&format!("#EXT-X-VERSION:{ver}\n")), "{pl}");
    assert!(
        pl.contains("#EXT-X-MEDIA:TYPE=AUDIO,GROUP-ID=\"aac\",NAME=\"Main\",LANGUAGE=\"en\",DEFAULT=YES,AUTOSELECT=YES,CHANNELS=\"2\",URI=\"cam_audio/index.m3u8?k=v\""),
        "{pl}"
    );
    let infs: Vec<&str> = pl
        .lines()
        .filter(|l| l.starts_with("#EXT-X-STREAM-INF:"))
        .collect();
    assert_eq!(infs.len(), 2, "{pl}");
    assert!(
        infs[0].contains("CODECS=\"hvc1.1.6.L60.90,mp4a.40.2\""),
        "{pl}"
    );
    assert!(infs[0].contains("AVERAGE-BANDWIDTH="), "{pl}");
    assert!(
        infs[1].starts_with("#EXT-X-STREAM-INF:BANDWIDTH=400000,CODECS=\"avc1.64000D,mp4a.40.2\""),
        "{pl}"
    );
    for l in &infs {
        assert!(
            l.contains("RESOLUTION=320x240") && l.contains("AUDIO=\"aac\""),
            "{l}"
        );
    }
    // Every URI leads to a live media playlist.
    for uri in [
        "cam_hevc/index.m3u8?k=v",
        "cam_avc/index.m3u8?k=v",
        "cam_audio/index.m3u8?k=v",
    ] {
        assert!(pl.contains(uri), "{pl}");
        let (status, _, body) = get(addr, &format!("/live/{uri}"));
        assert_eq!(status, 200, "{uri}");
        let media = String::from_utf8(body).unwrap();
        assert!(media.contains("#EXTINF"), "{media}");
        assert_eq!(parts, media.contains("#EXT-X-PART:"), "{media}");
    }
    // Unknown multivariant names stay 404; removing one makes it 404.
    assert_eq!(get(addr, "/live/nope.m3u8").0, 404);

    if have("ffprobe") && have("ffmpeg") {
        let url = format!("http://{addr}/live/cam.m3u8");
        let out = Command::new("ffprobe")
            .args([
                "-v",
                "error",
                "-show_entries",
                "stream=codec_name,width,height",
            ])
            .args(["-of", "csv=p=0", &url])
            .output()
            .unwrap();
        let streams = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        for want in ["hevc,320,240", "h264,320,240", "aac"] {
            assert!(streams.contains(want), "{streams}");
        }
        let out = Command::new("ffmpeg")
            .args([
                "-nostdin", "-v", "error", "-i", &url, "-map", "0", "-t", "3",
            ])
            .args(["-f", "null", "-"])
            .output()
            .unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success() && err.trim().is_empty(), "{err}");
    } else {
        eprintln!("ffmpeg/ffprobe not found: ffmpeg checks skipped");
    }
    assert!(hls.remove_multivariant("live/cam"));
    assert_eq!(get(addr, "/live/cam.m3u8").0, 404);
    stop.store(true, Ordering::Release);
    for p in publishers {
        p.join().unwrap();
    }
    engine.shutdown();
}

#[test]
fn multivariant_mpegts() {
    check(SegmentFormat::MpegTs, false);
}

#[test]
fn multivariant_fmp4_low_latency() {
    check(SegmentFormat::Fmp4, true);
}
