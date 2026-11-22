//! Interop with ffmpeg's libsrt: ffmpeg publishes into the `akio` SRT server, ffprobe and ffmpeg
//! read back, with and without encryption. Skipped (passing) when `ffmpeg` / `ffprobe` are
//! missing or built without SRT (e.g. Homebrew's on macOS); run in Linux Docker with Debian's
//! ffmpeg.

use std::{
    process::{Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};

use akio::{Engine, Listener};
use akio_media::{
    Hub, PeerInfo,
    mpegts::demux::{Demuxer, Event as TsEvent},
    srt::{self, Config, SrtConfig, SrtServer},
};

fn have_srt() -> bool {
    let ok = |cmd: &str, args: &[&str]| {
        Command::new(cmd)
            .args(args)
            .stderr(Stdio::null())
            .output()
            .is_ok_and(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .any(|l| l.trim() == "srt")
            })
    };
    let probe = Command::new("ffprobe").arg("-version").output().is_ok();
    probe && ok("ffmpeg", &["-hide_banner", "-protocols"])
}

fn server(cfg: SrtConfig) -> (Arc<Engine>, Hub, u16) {
    let hub = Hub::default();
    let e = Engine::builder()
        .listen(
            Listener::udp("127.0.0.1:0".parse().unwrap()).serve(SrtServer::new(hub.clone(), cfg)),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    let port = e.local_addrs()[0].port();
    (Arc::new(e), hub, port)
}

fn publish(url: &str, secs: u32) -> std::process::Child {
    Command::new("ffmpeg")
        .args([
            "-hide_banner",
            "-loglevel",
            "error",
            "-re",
            "-f",
            "lavfi",
            "-i",
        ])
        .arg(format!("testsrc=size=320x240:rate=25:duration={secs}"))
        .args(["-f", "lavfi", "-i"])
        .arg(format!(
            "sine=frequency=440:sample_rate=48000:duration={secs}"
        ))
        .args([
            "-pix_fmt", "yuv420p", "-c:v", "libx264", "-g", "25", "-c:a", "aac", "-f", "mpegts",
        ])
        .arg(url)
        .stdout(Stdio::null())
        .spawn()
        .expect("spawn ffmpeg")
}

fn probe(url: &str) -> String {
    let o = Command::new("ffprobe")
        .args([
            "-hide_banner",
            "-v",
            "error",
            "-show_entries",
            "stream=codec_name,width,height,sample_rate",
            "-of",
            "compact",
        ])
        .arg(url)
        .output()
        .expect("ffprobe");
    String::from_utf8_lossy(&o.stdout).into_owned() + &String::from_utf8_lossy(&o.stderr)
}

fn wait_live(hub: &Hub, path: &str) {
    let end = Instant::now() + Duration::from_secs(15);
    while !hub
        .stream_info(path)
        .is_some_and(|s| s.publishing && s.packets_in > 30)
    {
        assert!(Instant::now() < end, "{path} never went live");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn run(passphrase: Option<&str>) {
    let mut cfg = SrtConfig::default();
    cfg.passphrase = passphrase.map(str::to_owned);
    let (_e, hub, port) = server(cfg);
    let pass = passphrase.map_or(String::new(), |p| format!("&passphrase={p}&pbkeylen=16"));
    let pub_url = format!("srt://127.0.0.1:{port}?streamid=#!::r=live/s,m=publish{pass}");
    let mut ff = publish(&pub_url, 8);
    wait_live(&hub, "live/s");
    let info = hub.stream_info("live/s").unwrap();
    assert_eq!(info.tracks.len(), 2, "{info:?}");

    let play_url = format!("srt://127.0.0.1:{port}?streamid=#!::r=live/s,m=request{pass}");
    let out = probe(&play_url);
    eprintln!("ffprobe {play_url}: {out}");
    assert!(
        out.contains("codec_name=h264|width=320|height=240"),
        "{out}"
    );
    assert!(out.contains("codec_name=aac"), "{out}");

    // ffmpeg reading two seconds and remuxing: decodable throughout.
    let o = Command::new("ffmpeg")
        .args(["-hide_banner", "-v", "error", "-i"])
        .arg(&play_url)
        .args(["-t", "2", "-f", "null", "-"])
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let _ = ff.kill();
    let _ = ff.wait();
}

#[test]
fn ffmpeg_publish_ffprobe_play() {
    if !have_srt() {
        eprintln!("skipped: ffmpeg/ffprobe with SRT not found");
        return;
    }
    run(None);
}

#[test]
fn ffmpeg_publish_ffprobe_play_encrypted() {
    if !have_srt() {
        eprintln!("skipped: ffmpeg/ffprobe with SRT not found");
        return;
    }
    run(Some("0123456789secret"));
}

fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn client_engine() -> Arc<Engine> {
    let e = Engine::builder().udp_client_threads(1).build().unwrap();
    e.start().unwrap();
    Arc::new(e)
}

/// `akio` as caller: pushes a hub stream (the sample file, paced) to ffmpeg listening.
#[test]
fn akio_push_to_ffmpeg_listener() {
    if !have_srt() {
        eprintln!("skipped: ffmpeg/ffprobe with SRT not found");
        return;
    }
    let port = free_udp_port();
    let dir = std::env::temp_dir().join(format!("akio-srt-{port}"));
    std::fs::create_dir_all(&dir).unwrap();
    let out = dir.join("out.ts");
    let mut ff = Command::new("ffmpeg")
        .args(["-hide_banner", "-loglevel", "error", "-y", "-i"])
        .arg(format!("srt://127.0.0.1:{port}?mode=listener"))
        .args(["-c", "copy", "-f", "mpegts"])
        .arg(&out)
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_millis(500));
    let hub = Hub::default();
    // Publish the sample file into the hub, looping it with paced writes.
    let ts = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/h264_aac.ts")).unwrap();
    let mut d = Demuxer::new();
    let mut evs = Vec::new();
    let _ = d.feed(&ts, &mut |e| evs.push(e));
    d.flush(&mut |e| evs.push(e));
    let TsEvent::Tracks(tracks) = evs[0].clone() else {
        panic!("no tracks first")
    };
    let publisher = hub.publish("live/s", tracks, PeerInfo::default()).unwrap();
    let e = client_engine();
    let s = srt::push(
        &e,
        format!("127.0.0.1:{port}").parse().unwrap(),
        Config::default(),
        &hub,
        "live/s",
    )
    .unwrap();
    let start = Instant::now();
    for e in evs.into_iter().skip(1) {
        if let TsEvent::Packet(p) = e {
            let due = Duration::from_nanos(u64::try_from(p.dts - 1_400_000_000).unwrap_or(0));
            if let Some(w) = due.checked_sub(start.elapsed()) {
                std::thread::sleep(w);
            }
            publisher.write(p);
        }
    }
    std::thread::sleep(Duration::from_millis(500));
    assert!(s.stats().packets_sent > 10, "{:?}", s.stats());
    s.close();
    let st = ff.wait().unwrap();
    assert!(st.success());
    let out = probe(out.to_str().unwrap());
    eprintln!("ffprobe pushed file: {out}");
    assert!(
        out.contains("codec_name=h264|width=320|height=240"),
        "{out}"
    );
    assert!(out.contains("codec_name=aac"), "{out}");
    let _ = std::fs::remove_dir_all(dir);
}

/// `akio` as caller: pulls from ffmpeg listening and publishes into the hub.
#[test]
fn akio_pull_from_ffmpeg_listener() {
    if !have_srt() {
        eprintln!("skipped: ffmpeg/ffprobe with SRT not found");
        return;
    }
    let port = free_udp_port();
    let mut ff = publish(&format!("srt://127.0.0.1:{port}?mode=listener"), 8);
    std::thread::sleep(Duration::from_millis(800));
    let hub = Hub::default();
    let e = client_engine();
    let _s = srt::pull(
        &e,
        format!("127.0.0.1:{port}").parse().unwrap(),
        Config::default(),
        &hub,
        "live/p",
    )
    .unwrap();
    wait_live(&hub, "live/p");
    assert_eq!(hub.stream_info("live/p").unwrap().tracks.len(), 2);
    let _ = ff.kill();
    let _ = ff.wait();
}
