//! RTMP client tests: akio's client against akio's server both ways (push hub A to the
//! server's hub B, pull from hub B into hub C), against ffmpeg (`-listen 1` as the server it
//! pushes to and pulls from; skipped when ffmpeg/ffprobe are not installed), and against
//! mediamtx in Docker (ignored by default:
//! `cargo test -p akio-media --test rtmp_client -- --ignored mediamtx`).

use std::{
    net::{SocketAddr, TcpListener},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use akio::{Engine, Listener};
use akio_media::{
    Codec, Hub, Packet, PeerInfo, Publisher, Sink, SubscribeOptions, Subscription, Tracks,
    av::SECOND,
    flv::{Decoder, Demuxer, Event},
    hub::HubError,
    rtmp::{
        RtmpConfig, RtmpServer,
        client::{self, ClientError, ClientState, RtmpClient, RtmpClientConfig},
    },
};

const H264: &[u8] = include_bytes!("../testdata/h264_aac.flv");
const H265: &[u8] = include_bytes!("../testdata/h265_aac.flv");

fn testdata(name: &str) -> String {
    format!("{}/testdata/{name}", env!("CARGO_MANIFEST_DIR"))
}

/// Tracks and packets of an FLV file.
fn decode(flv: &[u8]) -> (Tracks, Vec<Packet>) {
    let mut dec = Decoder::new();
    let mut tracks = None;
    let mut pkts = Vec::new();
    for t in Demuxer::new().feed(flv).unwrap() {
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

fn video_count(flv: &[u8]) -> usize {
    decode(flv).1.iter().filter(|p| p.track == 0).count()
}

/// Publishes `flv` at `path` in one go.
fn publish_all(hub: &Hub, path: &str, flv: &[u8]) -> Publisher {
    let (tracks, pkts) = decode(flv);
    let p = hub.publish(path, tracks, PeerInfo::default()).unwrap();
    for pkt in pkts {
        p.write(pkt);
    }
    p
}

/// Publishes `flv` at `path` `loops` times in real time on a thread.
fn publish_paced(hub: &Hub, path: &str, flv: &[u8], loops: usize) -> std::thread::JoinHandle<()> {
    let (tracks, pkts) = decode(flv);
    let p = hub.publish(path, tracks, PeerInfo::default()).unwrap();
    let span = pkts.iter().map(|p| p.dts).max().unwrap() + SECOND / 25;
    std::thread::spawn(move || {
        let start = Instant::now();
        for n in 0..loops {
            let off = span * n as i64;
            for pkt in &pkts {
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
        drop(p);
    })
}

#[derive(Default)]
struct Counts {
    tracks: Mutex<Option<Tracks>>,
    video: AtomicUsize,
    audio: AtomicUsize,
    closed: AtomicBool,
}

struct Count(Arc<Counts>);

impl Sink for Count {
    fn on_tracks(&mut self, t: &Tracks) {
        *self.0.tracks.lock().unwrap() = Some(t.clone());
    }
    fn on_packet(&mut self, p: &Arc<Packet>) {
        if p.track == 0 {
            self.0.video.fetch_add(1, Ordering::Relaxed);
        } else {
            self.0.audio.fetch_add(1, Ordering::Relaxed);
        }
    }
    fn on_close(&mut self, _err: HubError) {
        self.0.closed.store(true, Ordering::Relaxed);
    }
}

fn count(hub: &Hub, path: &str) -> (Arc<Counts>, Subscription) {
    let c = Arc::new(Counts::default());
    let mut o = SubscribeOptions::new(PeerInfo::default());
    o.start_wait = Some(Duration::from_secs(30));
    let sub = hub.subscribe(path, Count(c.clone()), o).unwrap();
    (c, sub)
}

impl Counts {
    fn codecs(&self) -> Vec<Codec> {
        self.tracks
            .lock()
            .unwrap()
            .as_ref()
            .map(|t| t.iter().map(|t| t.codec).collect())
            .unwrap_or_default()
    }
}

fn wait_for(what: &str, secs: u64, mut f: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while !f() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn client_engine() -> Engine {
    let e = Engine::builder().client_threads(1).build().unwrap();
    e.start().unwrap();
    e
}

fn server(cfg: RtmpConfig) -> (Hub, Engine, SocketAddr) {
    let hub = Hub::default();
    let e = Engine::builder()
        .listen(
            Listener::tcp("127.0.0.1:0".parse().unwrap()).serve(RtmpServer::new(hub.clone(), cfg)),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    (hub, e, addr)
}

fn streaming(c: &RtmpClient) -> bool {
    assert!(!c.is_closed(), "client ended: {:?}", c.error());
    c.state() == ClientState::Streaming
}

/// Push hub A -> akio's RTMP server (hub B) -> pull into hub C, H.264/AAC and H.265/AAC
/// (Enhanced RTMP `hvc1` both ways).
#[test]
fn loopback_push_and_pull_through_only_server() {
    let mut cfg = RtmpConfig::default();
    cfg.play_wait = Some(Duration::from_secs(10));
    let (hub_b, _srv, addr) = server(cfg);
    let e = client_engine();
    for (flv, video) in [(H264, Codec::H264), (H265, Codec::H265)] {
        let hub_a = Hub::default();
        let hub_c = Hub::default();
        let url = format!("rtmp://{addr}/live/s?token=1");
        // The player first: the server lets it wait for the publisher.
        let puller = client::pull(&e, &url, &hub_c, "pulled", RtmpClientConfig::default()).unwrap();
        wait_for("pull streaming", 10, || streaming(&puller));
        let (in_b, _sb) = count(&hub_b, "live/s");
        let (in_c, _sc) = count(&hub_c, "pulled");
        let pusher = client::push(&e, &url, &hub_a, "src", RtmpClientConfig::default()).unwrap();
        wait_for("push subscribed", 10, || {
            streaming(&pusher) && hub_a.stream_info("src").is_some_and(|s| s.subscribers == 1)
        });
        let want = video_count(flv);
        let source = publish_all(&hub_a, "src", flv);
        wait_for("video in C", 10, || {
            in_c.video.load(Ordering::Relaxed) >= want
        });
        assert_eq!(in_b.video.load(Ordering::Relaxed), want);
        assert_eq!(in_c.video.load(Ordering::Relaxed), want);
        assert_eq!(
            in_b.audio.load(Ordering::Relaxed),
            in_c.audio.load(Ordering::Relaxed)
        );
        assert!(in_c.audio.load(Ordering::Relaxed) > 0);
        assert_eq!(in_c.codecs(), [video, Codec::Aac]);
        assert_eq!(
            hub_b.stream_info("live/s").unwrap().publisher.query,
            "token=1"
        );
        // The source leaves: the push ends, the server's stream with it.
        drop(source);
        wait_for("push end", 10, || pusher.is_closed());
        assert_eq!(
            pusher.error(),
            Some(ClientError::Hub(HubError::Unpublished))
        );
        wait_for("B closed", 10, || in_b.closed.load(Ordering::Relaxed));
        assert!(!puller.is_closed(), "the server keeps its player waiting");
        puller.close();
        wait_for("C unpublished", 10, || in_c.closed.load(Ordering::Relaxed));
        assert_eq!(puller.error(), None);
    }
}

fn have(tool: &str) -> bool {
    Command::new(tool)
        .arg("-version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Kill(Child);

impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Kill {
    fn wait_exit(&mut self, secs: u64) -> bool {
        let deadline = Instant::now() + Duration::from_secs(secs);
        while Instant::now() < deadline {
            if let Ok(Some(s)) = self.0.try_wait() {
                return s.success();
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        false
    }
}

/// Starts a client until the server listens: a refused connection is retried.
fn until_connected(mut start: impl FnMut() -> RtmpClient) -> RtmpClient {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let c = start();
        while matches!(c.state(), ClientState::Connecting) {
            std::thread::sleep(Duration::from_millis(10));
        }
        if !matches!(c.error(), Some(ClientError::Connect(_))) {
            return c;
        }
        drop(c);
        assert!(Instant::now() < deadline, "server never listened");
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// `(codec_name, packets)` of each stream of `path`.
fn ffprobe_packets(path: &str) -> Vec<(String, usize)> {
    let out = Command::new("ffprobe")
        .args([
            "-v",
            "error",
            "-count_packets",
            "-show_entries",
            "stream=codec_name,nb_read_packets",
            "-of",
            "csv=p=0",
            path,
        ])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| {
            let (c, n) = l.trim().split_once(',')?;
            Some((c.to_owned(), n.parse().ok()?))
        })
        .collect()
}

fn out_file(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("akio-rtmp-client-{}-{name}", std::process::id()))
}

/// ffmpeg as the server our push publishes to (`ffmpeg -listen 1 -i rtmp://...`), then
/// ffprobe counts what it wrote.
#[test]
fn ffmpeg_receives_a_push() {
    if !have("ffmpeg") || !have("ffprobe") {
        eprintln!("ffmpeg/ffprobe not found: skipped");
        return;
    }
    let e = client_engine();
    for (flv, name, codec) in [(H264, "h264", "h264"), (H265, "h265", "hevc")] {
        let port = free_port();
        let url = format!("rtmp://127.0.0.1:{port}/live/s");
        let out = out_file(&format!("{name}.flv"));
        let mut ff = Kill(
            Command::new("ffmpeg")
                .args(["-v", "error", "-listen", "1", "-timeout", "20", "-i", &url])
                .args(["-c", "copy", "-f", "flv", "-y"])
                .arg(&out)
                .stdin(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let hub = Hub::default();
        let pusher = until_connected(|| {
            client::push(&e, &url, &hub, "src", RtmpClientConfig::default()).unwrap()
        });
        wait_for("push subscribed", 10, || {
            streaming(&pusher) && hub.stream_info("src").is_some_and(|s| s.subscribers == 1)
        });
        let source = publish_all(&hub, "src", flv);
        // Let it drain, then the source leaves and the push unpublishes.
        std::thread::sleep(Duration::from_millis(300));
        drop(source);
        wait_for("push end", 10, || pusher.is_closed());
        assert!(ff.wait_exit(20), "ffmpeg failed or hung");
        let probe = ffprobe_packets(out.to_str().unwrap());
        let _ = std::fs::remove_file(&out);
        assert_eq!(
            probe.iter().find(|(c, _)| c == codec).map(|p| p.1),
            Some(video_count(flv)),
            "{name}: ffprobe said {probe:?}"
        );
        assert!(
            probe.iter().any(|(c, n)| c == "aac" && *n > 0),
            "{name}: ffprobe said {probe:?}"
        );
    }
}

/// ffmpeg as the server our pull plays from (`ffmpeg -re -i file -f flv -listen 1 rtmp://...`).
#[test]
fn ffmpeg_serves_a_pull() {
    if !have("ffmpeg") {
        eprintln!("ffmpeg not found: skipped");
        return;
    }
    let e = client_engine();
    for (flv, file, codec) in [
        (H264, "h264_aac.flv", Codec::H264),
        (H265, "h265_aac.flv", Codec::H265),
    ] {
        let port = free_port();
        let url = format!("rtmp://127.0.0.1:{port}/live/s");
        let mut ff = Kill(
            Command::new("ffmpeg")
                .args(["-v", "error", "-re", "-i", &testdata(file)])
                .args([
                    "-c", "copy", "-f", "flv", "-listen", "1", "-timeout", "20", &url,
                ])
                .stdin(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let hub = Hub::default();
        let (got, _sub) = count(&hub, "pulled");
        let puller = until_connected(|| {
            client::pull(&e, &url, &hub, "pulled", RtmpClientConfig::default()).unwrap()
        });
        // ffmpeg sends the file in real time and closes at its end.
        wait_for("pull end", 20, || puller.is_closed());
        assert!(
            matches!(puller.error(), Some(ClientError::Disconnected(_))),
            "{:?}",
            puller.error()
        );
        assert!(ff.wait_exit(10), "ffmpeg failed");
        assert_eq!(got.codecs(), [codec, Codec::Aac], "{file}");
        assert_eq!(
            got.video.load(Ordering::Relaxed),
            video_count(flv),
            "{file}"
        );
        assert!(got.audio.load(Ordering::Relaxed) > 0);
        assert!(got.closed.load(Ordering::Relaxed), "unpublished at the end");
    }
}

struct Container(String);

impl Drop for Container {
    fn drop(&mut self) {
        if std::thread::panicking() {
            if let Ok(o) = Command::new("docker").args(["logs", &self.0]).output() {
                eprintln!(
                    "mediamtx logs:\n{}{}",
                    String::from_utf8_lossy(&o.stdout),
                    String::from_utf8_lossy(&o.stderr)
                );
            }
        }
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.0])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

/// mediamtx in Docker: push to it, pull it back, and ffprobe it. Needs Docker and the
/// `bluenviron/mediamtx` image:
/// `cargo test -p akio-media --test rtmp_client -- --ignored mediamtx`.
#[test]
#[ignore = "needs Docker (bluenviron/mediamtx); run with --ignored"]
fn mediamtx_push_and_pull() {
    let port = free_port();
    let out = Command::new("docker")
        .args(["run", "--rm", "-d", "-p"])
        .arg(format!("127.0.0.1:{port}:1935"))
        .arg("bluenviron/mediamtx:latest")
        .output()
        .expect("docker");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let _c = Container(String::from_utf8_lossy(&out.stdout).trim().to_owned());
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    // Docker Desktop accepts on the mapped port before mediamtx listens: wait for its log line.
    wait_for("mediamtx", 30, || {
        Command::new("docker")
            .args(["logs", &_c.0])
            .output()
            .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("[RTMP] started"))
    });
    let e = client_engine();
    for (flv, codec, name) in [(H264, Codec::H264, "h264"), (H265, Codec::H265, "hevc")] {
        let url = format!("rtmp://{addr}/live/{name}");
        let hub_a = Hub::default();
        let hub_c = Hub::default();
        let pusher = until_connected(|| {
            client::push(&e, &url, &hub_a, "src", RtmpClientConfig::default()).unwrap()
        });
        wait_for("push subscribed", 10, || {
            streaming(&pusher) && hub_a.stream_info("src").is_some_and(|s| s.subscribers == 1)
        });
        let feeder = publish_paced(&hub_a, "src", flv, 6);
        // mediamtx makes the path available once it has seen every track (about 2 s): a pull
        // before that is closed ("no stream is available"), so retry.
        let t = Instant::now();
        let mut attempt = 0;
        let (got, _sub, puller) = loop {
            attempt += 1;
            let path = format!("pulled{attempt}");
            let (got, sub) = count(&hub_c, &path);
            let puller = until_connected(|| {
                client::pull(&e, &url, &hub_c, &path, RtmpClientConfig::default()).unwrap()
            });
            while got.video.load(Ordering::Relaxed) < 25 && !puller.is_closed() {
                std::thread::sleep(Duration::from_millis(10));
            }
            if got.video.load(Ordering::Relaxed) >= 25 {
                break (got, sub, puller);
            }
            if t.elapsed() > Duration::from_secs(10) {
                let logs = Command::new("docker")
                    .args(["logs", &_c.0])
                    .output()
                    .unwrap();
                panic!(
                    "pull: {:?} video {}\n{}{}",
                    puller.error(),
                    got.video.load(Ordering::Relaxed),
                    String::from_utf8_lossy(&logs.stdout),
                    String::from_utf8_lossy(&logs.stderr)
                );
            }
            std::thread::sleep(Duration::from_millis(300));
        };
        assert_eq!(got.codecs(), [codec, Codec::Aac], "{name}");
        assert!(got.audio.load(Ordering::Relaxed) > 0);
        if have("ffprobe") {
            let probe = Command::new("ffprobe")
                .args(["-v", "error", "-rw_timeout", "5000000"])
                // mediamtx sends H.265 only to a client announcing it (Enhanced RTMP).
                .args(["-rtmp_enhanced_codecs", "hvc1,mp4a"])
                .args(["-show_entries", "stream=codec_name", "-of", "csv=p=0", &url])
                .output()
                .unwrap();
            let probe = String::from_utf8_lossy(&probe.stdout).into_owned();
            assert!(probe.contains(name) && probe.contains("aac"), "{probe:?}");
        }
        feeder.join().unwrap();
        wait_for("push end", 10, || pusher.is_closed());
        assert_eq!(
            pusher.error(),
            Some(ClientError::Hub(HubError::Unpublished))
        );
        wait_for("pull end", 15, || puller.is_closed());
    }
}

/// The server's host name moves to another address while the clients reconnect: a push and a
/// pull of `rtmp://$AKIO_MOVING_RTMP/live/mv`, both reconnecting, must find the server at
/// its new address (the name is looked up again on every try). Run by
/// `tools/interop/media/rtsp-server-redirect.sh rtmp`, which moves the name `rtmpsrv` from one
/// mediamtx container to another on a Docker network; skipped without the variable.
#[test]
fn rtmp_server_moves_to_another_address() {
    use std::io::Write as _;
    let Ok(srv) = std::env::var("AKIO_MOVING_RTMP") else {
        eprintln!(
            "AKIO_MOVING_RTMP not set: skipped (see tools/interop/media/rtsp-server-redirect.sh)"
        );
        return;
    };
    let e = Arc::new(client_engine());
    let mut cfg = RtmpClientConfig::default();
    cfg.reconnect = Some(
        akio_media::Reconnect::new(&e)
            .initial_delay(Duration::from_millis(200))
            .max_delay(Duration::from_secs(1)),
    );
    let hub = Hub::default();
    let _feeder = publish_paced(&hub, "src", H264, 1000);
    let url = format!("rtmp://{srv}/live/mv");
    let push = client::push(&e, &url, &hub, "src", cfg.clone()).unwrap();
    let (got, _sub) = count(&hub, "back");
    let pull = client::pull(&e, &url, &hub, "back", cfg).unwrap();
    wait_for("media back", 30, || got.video.load(Ordering::Relaxed) > 50);
    let first = (push.addr(), pull.addr());
    println!("READY: push {} pull {}", first.0, first.1);
    std::io::stdout().flush().unwrap();
    let secs = std::env::var("AKIO_MOVING_WAIT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(120);
    wait_for("both reconnected", secs, || {
        push.reconnects() >= 1
            && pull.reconnects() >= 1
            && push.state() == ClientState::Streaming
            && pull.state() == ClientState::Streaming
    });
    let before = got.video.load(Ordering::Relaxed);
    wait_for("media from the new server", 30, || {
        got.video.load(Ordering::Relaxed) > before + 50
    });
    assert_ne!(push.addr(), first.0, "push dialed the old address");
    assert_ne!(pull.addr(), first.1, "pull dialed the old address");
    println!(
        "MOVED: push {} -> {} ({} reconnects), pull {} -> {} ({} reconnects)",
        first.0,
        push.addr(),
        push.reconnects(),
        first.1,
        pull.addr(),
        pull.reconnects()
    );
    drop((push, pull));
}
