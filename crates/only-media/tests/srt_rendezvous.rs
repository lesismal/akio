//! SRT rendezvous against libsrt's `srt-live-transmit`: `only` pulls what srt-live-transmit
//! relays from ffmpeg, and pushes a hub stream that srt-live-transmit writes out for ffprobe,
//! in the clear and encrypted.
//!
//! `SRT_LIVE_TRANSMIT` is the command that runs srt-live-transmit (split on spaces; default
//! `srt-live-transmit`), e.g. `docker run --rm -i --network host only-srt-tools
//! srt-live-transmit` with an image of Debian's `srt-tools`. Skipped (passing) when it, `ffmpeg`
//! or `ffprobe` cannot run. (ffmpeg's own `mode=rendezvous` binds to the URL's address and
//! connects to the same, so it cannot meet a peer on another port.)

use std::{
    net::SocketAddr,
    process::{Child, Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};

use only::Engine;
use only_media::{
    Hub, PeerInfo,
    mpegts::demux::{Demuxer, Event as TsEvent},
    srt::{self, Config},
};

fn slt() -> Vec<String> {
    std::env::var("SRT_LIVE_TRANSMIT")
        .unwrap_or_else(|_| "srt-live-transmit".to_owned())
        .split_whitespace()
        .map(str::to_owned)
        .collect()
}

fn available() -> bool {
    let cmd = slt();
    let slt_ok = Command::new(&cmd[0])
        .args(&cmd[1..])
        .arg("-version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    let ff = |c: &str| Command::new(c).arg("-version").output().is_ok();
    slt_ok && ff("ffmpeg") && ff("ffprobe")
}

fn spawn_slt(args: &[String], stdout: Stdio) -> Child {
    let cmd = slt();
    Command::new(&cmd[0])
        .args(&cmd[1..])
        .args(args)
        .stdout(stdout)
        .spawn()
        .expect("spawn srt-live-transmit")
}

fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn engine() -> Arc<Engine> {
    let e = Engine::builder().udp_client_threads(1).build().unwrap();
    e.start().unwrap();
    Arc::new(e)
}

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

fn srt_url(peer: u16, local: u16, pass: Option<&str>) -> String {
    let pass = pass.map_or(String::new(), |p| format!("&passphrase={p}&pbkeylen=16"));
    format!("srt://127.0.0.1:{peer}?mode=rendezvous&port={local}&latency=200{pass}")
}

fn cfg(pass: Option<&str>) -> Config {
    let mut c = Config::default().latency(Duration::from_millis(200));
    c.passphrase = pass.map(str::to_owned);
    c
}

fn pull(pass: Option<&str>) {
    let (input, mine, theirs) = (free_udp_port(), free_udp_port(), free_udp_port());
    // srt-live-transmit: UDP in (from ffmpeg), SRT rendezvous out to us.
    let mut relay = spawn_slt(
        &[
            "-q".into(),
            "-a:no".into(),
            "-t:20".into(),
            format!("udp://127.0.0.1:{input}"),
            srt_url(mine, theirs, pass),
        ],
        Stdio::null(),
    );
    std::thread::sleep(Duration::from_millis(300));
    let hub = Hub::default();
    let e = engine();
    let s =
        srt::pull_rendezvous(&e, addr(mine), addr(theirs), cfg(pass), &hub, "live/rdv").unwrap();
    let mut ff = Command::new("ffmpeg")
        .args(["-hide_banner", "-loglevel", "error", "-re", "-f", "lavfi"])
        .args(["-i", "testsrc=size=320x240:rate=25:duration=10"])
        .args([
            "-f",
            "lavfi",
            "-i",
            "sine=frequency=440:sample_rate=48000:duration=10",
        ])
        .args([
            "-pix_fmt", "yuv420p", "-c:v", "libx264", "-g", "25", "-c:a", "aac",
        ])
        .args(["-f", "mpegts"])
        .arg(format!("udp://127.0.0.1:{input}?pkt_size=1316"))
        .stdout(Stdio::null())
        .spawn()
        .expect("spawn ffmpeg");
    let end = Instant::now() + Duration::from_secs(15);
    while !hub
        .stream_info("live/rdv")
        .is_some_and(|i| i.publishing && i.packets_in > 50)
    {
        assert!(
            Instant::now() < end,
            "never went live: {:?} connected={}",
            s.stats(),
            s.is_connected()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let info = hub.stream_info("live/rdv").unwrap();
    let codecs: Vec<String> = info.tracks.iter().map(|t| t.codec.to_string()).collect();
    eprintln!("pulled over rendezvous: {codecs:?} {:?}", s.stats());
    assert_eq!(info.tracks.len(), 2, "{info:?}");
    assert!(info.tracks[0].codec.is_video() && info.tracks[0].width == 320);
    assert_eq!(s.stats().packets_undecrypt, 0);
    s.close();
    let _ = ff.kill();
    let _ = ff.wait();
    let _ = relay.kill();
    let _ = relay.wait();
}

fn push(pass: Option<&str>) {
    let (mine, theirs) = (free_udp_port(), free_udp_port());
    let dir = std::env::temp_dir().join(format!("only-srt-rdv-{mine}"));
    std::fs::create_dir_all(&dir).unwrap();
    let out = dir.join("out.ts");
    // srt-live-transmit: SRT rendezvous in (from us), the stream to a file.
    let mut relay = spawn_slt(
        &[
            "-q".into(),
            "-a:no".into(),
            "-t:12".into(),
            srt_url(mine, theirs, pass),
            "file://con".into(),
        ],
        Stdio::from(std::fs::File::create(&out).unwrap()),
    );
    let hub = Hub::default();
    let ts = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/h264_aac.ts")).unwrap();
    let mut d = Demuxer::new();
    let mut evs = Vec::new();
    let _ = d.feed(&ts, &mut |e| evs.push(e));
    d.flush(&mut |e| evs.push(e));
    let TsEvent::Tracks(tracks) = evs[0].clone() else {
        panic!("no tracks first")
    };
    let publisher = hub.publish("live/s", tracks, PeerInfo::default()).unwrap();
    let e = engine();
    let s = srt::push_rendezvous(&e, addr(mine), addr(theirs), cfg(pass), &hub, "live/s").unwrap();
    let end = Instant::now() + Duration::from_secs(8);
    while !s.is_connected() {
        assert!(Instant::now() < end, "rendezvous never connected");
        std::thread::sleep(Duration::from_millis(20));
    }
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
    std::thread::sleep(Duration::from_millis(600));
    let st = s.stats();
    assert!(st.packets_sent > 10, "{st:?}");
    s.close();
    let _ = relay.wait();
    let o = Command::new("ffprobe")
        .args(["-hide_banner", "-v", "error", "-show_entries"])
        .args(["stream=codec_name,width,height", "-of", "compact"])
        .arg(&out)
        .output()
        .unwrap();
    let probe = String::from_utf8_lossy(&o.stdout).into_owned();
    eprintln!("ffprobe of what srt-live-transmit got: {probe} ({st:?})");
    assert!(
        probe.contains("codec_name=h264|width=320|height=240"),
        "{probe}"
    );
    assert!(probe.contains("codec_name=aac"), "{probe}");
    let o = Command::new("ffmpeg")
        .args(["-hide_banner", "-v", "error", "-i"])
        .arg(&out)
        .args(["-f", "null", "-"])
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn rendezvous_pull_from_srt_live_transmit() {
    if !available() {
        eprintln!("skipped: srt-live-transmit / ffmpeg / ffprobe not found");
        return;
    }
    pull(None);
}

#[test]
fn rendezvous_pull_from_srt_live_transmit_encrypted() {
    if !available() {
        eprintln!("skipped: srt-live-transmit / ffmpeg / ffprobe not found");
        return;
    }
    pull(Some("rendezvous-secret"));
}

#[test]
fn rendezvous_push_to_srt_live_transmit() {
    if !available() {
        eprintln!("skipped: srt-live-transmit / ffmpeg / ffprobe not found");
        return;
    }
    push(None);
}

#[test]
fn rendezvous_push_to_srt_live_transmit_encrypted() {
    if !available() {
        eprintln!("skipped: srt-live-transmit / ffmpeg / ffprobe not found");
        return;
    }
    push(Some("rendezvous-secret"));
}

/// Two `only` engines meet each other: a push and a pull over one rendezvous.
#[test]
fn rendezvous_only_to_only() {
    let (a, b) = (free_udp_port(), free_udp_port());
    let src = Hub::default();
    let dst = Hub::default();
    let ts = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/h264_aac.ts")).unwrap();
    let mut d = Demuxer::new();
    let mut evs = Vec::new();
    let _ = d.feed(&ts, &mut |e| evs.push(e));
    d.flush(&mut |e| evs.push(e));
    let TsEvent::Tracks(tracks) = evs[0].clone() else {
        panic!("no tracks first")
    };
    let publisher = src.publish("live/a", tracks, PeerInfo::default()).unwrap();
    let e = engine();
    let pass = Some("0123456789abcdef");
    let pusher = srt::push_rendezvous(&e, addr(a), addr(b), cfg(pass), &src, "live/a").unwrap();
    std::thread::sleep(Duration::from_millis(200));
    let puller = srt::pull_rendezvous(&e, addr(b), addr(a), cfg(pass), &dst, "live/b").unwrap();
    let end = Instant::now() + Duration::from_secs(5);
    while !(pusher.is_connected() && puller.is_connected()) {
        assert!(Instant::now() < end, "never connected");
        std::thread::sleep(Duration::from_millis(10));
    }
    for e in evs.into_iter().skip(1) {
        if let TsEvent::Packet(p) = e {
            publisher.write(p);
        }
    }
    let end = Instant::now() + Duration::from_secs(10);
    while !dst
        .stream_info("live/b")
        .is_some_and(|i| i.publishing && i.packets_in > 50)
    {
        assert!(Instant::now() < end, "{:?}", puller.stats());
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(dst.stream_info("live/b").unwrap().tracks.len(), 2);
    pusher.close();
    puller.close();
}
