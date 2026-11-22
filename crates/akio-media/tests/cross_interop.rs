//! Cross-protocol playback through one hub with ffmpeg as publisher and ffprobe as player:
//! RTSP in -> RTMP, HTTP-FLV, HLS and RTSP out; RTMP in -> RTSP out (skipped without ffmpeg).

use std::{
    process::{Child, Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};

use akio::{Engine, Listener};
use akio_http::{Router, serve};
use akio_media::{
    Hub,
    hls::{Hls, HlsConfig},
    http::MediaHttp,
    httpflv::{HttpFlv, HttpFlvConfig},
    rtmp::{RtmpConfig, RtmpServer},
    rtsp::{RtspConfig, RtspServer},
};

fn have(tool: &str) -> bool {
    Command::new(tool)
        .arg("-version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn ffprobe(args: &[&str], url: &str) -> String {
    let out = Command::new("ffprobe")
        .args([
            "-v",
            "error",
            "-show_entries",
            "stream=codec_name,width,height",
            "-of",
            "csv=p=0",
        ])
        .args(args)
        .arg(url)
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn publish(args: &[&str]) -> Child {
    Command::new("ffmpeg")
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
            "sine=sample_rate=48000",
        ])
        .args([
            "-t", "15", "-pix_fmt", "yuv420p", "-c:v", "libx264", "-g", "25", "-bf", "0", "-c:a",
            "aac",
        ])
        .args(args)
        .stdin(Stdio::null())
        .spawn()
        .unwrap()
}

fn wait_live(hub: &Hub, path: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while hub.stream_info(path).is_none_or(|s| !s.publishing) {
        assert!(Instant::now() < deadline, "{path} never went live");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn ffmpeg_across_protocols() {
    if !have("ffmpeg") || !have("ffprobe") {
        eprintln!("ffmpeg/ffprobe not found: skipped");
        return;
    }
    let hub = Hub::default();
    let rtsp = RtspServer::new(hub.clone(), RtspConfig::default());
    rtsp.listen_udp("127.0.0.1:0".parse().unwrap()).unwrap();
    let mut hcfg = HlsConfig::default();
    hcfg.target_duration = Duration::from_secs(1);
    let media = MediaHttp::new()
        .flv(HttpFlv::new(hub.clone(), HttpFlvConfig::default()))
        .hls(Hls::new(hub.clone(), hcfg));
    let engine = Arc::new(
        Engine::builder()
            .listen(
                Listener::tcp("127.0.0.1:0".parse().unwrap())
                    .serve(RtmpServer::new(hub.clone(), RtmpConfig::default())),
            )
            .listen(Listener::tcp("127.0.0.1:0".parse().unwrap()).serve(rtsp))
            .listen(
                Listener::tcp("127.0.0.1:0".parse().unwrap())
                    .serve(serve(Router::new().get("/*path", media))),
            )
            .build()
            .unwrap(),
    );
    engine.start().unwrap();
    let a = engine.local_addrs();
    let (rtmp, rtsp, http) = (a[0], a[1], a[2]);

    // RTSP in.
    let mut p = publish(&[
        "-f",
        "rtsp",
        "-rtsp_transport",
        "tcp",
        &format!("rtsp://{rtsp}/live/a"),
    ]);
    wait_live(&hub, "live/a");
    for (args, url) in [
        (
            vec!["-rw_timeout", "5000000"],
            format!("rtmp://{rtmp}/live/a"),
        ),
        (vec![], format!("http://{http}/live/a.flv")),
        (vec![], format!("http://{http}/live/a/index.m3u8")),
        (
            vec!["-rtsp_transport", "udp"],
            format!("rtsp://{rtsp}/live/a"),
        ),
    ] {
        let probe = ffprobe(&args, &url);
        assert!(
            probe.contains("h264,320,240") && probe.contains("aac"),
            "{url}: {probe:?}"
        );
    }
    let _ = p.kill();
    let _ = p.wait();

    // RTMP in, RTSP out.
    let mut p = publish(&["-f", "flv", &format!("rtmp://{rtmp}/live/b")]);
    wait_live(&hub, "live/b");
    let url = format!("rtsp://{rtsp}/live/b");
    let probe = ffprobe(&["-rtsp_transport", "tcp"], &url);
    assert!(
        probe.contains("h264,320,240") && probe.contains("aac"),
        "{url}: {probe:?}"
    );
    let _ = p.kill();
    let _ = p.wait();
    engine.shutdown();
}
