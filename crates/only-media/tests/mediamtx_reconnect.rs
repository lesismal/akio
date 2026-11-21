//! The RTMP and RTSP clients against mediamtx (Docker, `bluenviron/mediamtx`) that restarts:
//! with `reconnect`, pulls keep their hub path and the subscriber through `docker restart`
//! and republish once the stream is back, and pushes record to the restarted server again.
//! ffmpeg publishes a test pattern and a tone to mediamtx over RTSP in real time: in the RTSP
//! pull, whose tracks are lined up by mediamtx's RTCP sender reports (which come within the
//! first second, and move a track by up to about 130 ms from its arrival-based times), the
//! two tracks' times must keep about the same distance to their arrival (a skew within
//! 250 ms: the reports carry ffmpeg's and mediamtx's own clock estimates). Over TCP (Docker Desktop's NAT does not pass the client's UDP
//! ports). Needs Docker and ffmpeg:
//! `cargo test -p only-media --test mediamtx_reconnect -- --ignored --nocapture`.

use std::{
    net::{SocketAddr, TcpListener},
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use only::Engine;
use only_media::{
    Hub, Packet, PeerInfo, Reconnect, Sink, SubscribeOptions, Tracks,
    av::{MILLISECOND, Time},
    flv::{Decoder, Demuxer, Event},
    rtmp::client::{self as rtmp, RtmpClientConfig},
    rtsp::client::{self as rtsp, RtspClientConfig},
};

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn wait_for(what: &str, secs: u64, mut f: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while !f() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The container, removed when dropped.
struct Mtx {
    id: String,
    rtsp: SocketAddr,
    rtmp: SocketAddr,
}

impl Mtx {
    fn start() -> Mtx {
        let (rp, mp) = (free_port(), free_port());
        let out = Command::new("docker")
            .args(["run", "--rm", "-d"])
            .args(["-e", "MTX_RTSPTRANSPORTS=tcp"])
            .arg("-p")
            .arg(format!("127.0.0.1:{rp}:8554"))
            .arg("-p")
            .arg(format!("127.0.0.1:{mp}:1935"))
            .arg("bluenviron/mediamtx:latest")
            .output()
            .expect("docker");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let m = Mtx {
            id: String::from_utf8_lossy(&out.stdout).trim().to_owned(),
            rtsp: format!("127.0.0.1:{rp}").parse().unwrap(),
            rtmp: format!("127.0.0.1:{mp}").parse().unwrap(),
        };
        m.wait_ready(0);
        m
    }

    /// Waits for the `n`th start's listeners ("[RTMP] started" counted).
    fn wait_ready(&self, n: usize) {
        wait_for("mediamtx", 30, || {
            Command::new("docker")
                .args(["logs", &self.id])
                .output()
                .is_ok_and(|o| {
                    let log = String::from_utf8_lossy(&o.stdout).into_owned()
                        + &String::from_utf8_lossy(&o.stderr);
                    log.matches("[RTMP] started").count() > n
                        && log.matches("[RTSP] started").count() > n
                })
        });
    }

    /// `docker restart`: every session drops, the server comes back on the same ports.
    fn restart(&self, n: usize) {
        let st = Command::new("docker")
            .args(["restart", "-t", "0", &self.id])
            .stdout(Stdio::null())
            .status()
            .unwrap();
        assert!(st.success());
        self.wait_ready(n);
    }
}

impl Drop for Mtx {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.id])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

/// ffmpeg publishing a 320x240 pattern and a 440 Hz tone to `url`, in real time.
fn ffmpeg_publish(url: &str) -> Child {
    Command::new("ffmpeg")
        .args(["-nostdin", "-v", "error", "-re"])
        .args(["-f", "lavfi", "-i", "testsrc2=size=320x240:rate=25"])
        .args(["-f", "lavfi", "-i", "sine=frequency=440:sample_rate=48000"])
        .args(["-map", "0:v", "-map", "1:a", "-t", "120"])
        .args([
            "-c:v",
            "libx264",
            "-g",
            "25",
            "-bf",
            "0",
            "-preset",
            "ultrafast",
        ])
        .args(["-c:a", "aac", "-f", "rtsp", "-rtsp_transport", "tcp", url])
        .stdout(Stdio::null())
        .spawn()
        .expect("ffmpeg")
}

/// What a subscriber hears: tracks announcements and (track, pts, arrival) of every packet.
#[derive(Clone)]
struct Heard(Arc<Mutex<(usize, Vec<Arrival>)>>);

/// A packet's track, pts and arrival.
type Arrival = (usize, Time, Instant);

impl Default for Heard {
    fn default() -> Self {
        Heard(Arc::new(Mutex::new((0, Vec::new()))))
    }
}

impl Sink for Heard {
    fn on_tracks(&mut self, _t: &Tracks) {
        self.0.lock().unwrap().0 += 1;
    }
    fn on_packet(&mut self, p: &Arc<Packet>) {
        self.0
            .lock()
            .unwrap()
            .1
            .push((p.track, p.pts, Instant::now()));
    }
}

impl Heard {
    fn tracks(&self) -> usize {
        self.0.lock().unwrap().0
    }
    fn packets(&self) -> usize {
        self.0.lock().unwrap().1.len()
    }

    /// Audio's distance between its times and its arrival minus video's (medians over the
    /// packets after `from`): about zero when both are in step, as ffmpeg sends them.
    fn skew(&self, from: usize) -> Time {
        let g = self.0.lock().unwrap();
        let t0 = g.1.first().map_or_else(Instant::now, |x| x.2);
        let median = |t: usize| {
            let mut v: Vec<Time> =
                g.1.iter()
                    .skip(from)
                    .filter(|x| x.0 == t)
                    .map(|x| x.1 - x.2.duration_since(t0).as_nanos() as Time)
                    .collect();
            v.sort_unstable();
            v[v.len() / 2]
        };
        median(1) - median(0)
    }
}

fn subscribe(hub: &Hub, path: &str) -> (Heard, only_media::Subscription) {
    let h = Heard::default();
    let opts = SubscribeOptions::new(PeerInfo::default()).wait(Duration::from_secs(60));
    let sub = hub.subscribe(path, h.clone(), opts).unwrap();
    (h, sub)
}

fn reconnect(e: &Arc<Engine>) -> Reconnect {
    Reconnect::new(e)
        .initial_delay(Duration::from_millis(200))
        .max_delay(Duration::from_secs(1))
}

/// Publishes the H.264 + AAC sample at `path`, looped in real time, until `stop`.
fn feed(hub: &Hub, path: &str, stop: Arc<AtomicBool>) {
    let data = include_bytes!("../testdata/h264_aac.flv");
    let mut dec = Decoder::new();
    let (mut tracks, mut pkts) = (None, Vec::new());
    for t in Demuxer::new().feed(data).unwrap() {
        for e in dec.write(t.tag_type, t.ts, &t.body) {
            match e {
                Event::Tracks(t) => tracks = Some(t),
                Event::Packet(p) => pkts.push(p),
                _ => {}
            }
        }
    }
    let p = hub
        .publish(path, tracks.unwrap(), PeerInfo::default())
        .unwrap();
    std::thread::spawn(move || {
        let span = pkts.iter().map(|p| p.dts).max().unwrap_or(0) + 40 * MILLISECOND;
        let t0 = Instant::now();
        for round in 0.. {
            for pkt in &pkts {
                if stop.load(Ordering::Relaxed) {
                    return;
                }
                let at = Duration::from_nanos((pkt.dts + round * span).max(0) as u64);
                if let Some(d) = at.checked_sub(t0.elapsed()) {
                    std::thread::sleep(d);
                }
                let mut q = pkt.clone();
                q.dts += round * span;
                q.pts += round * span;
                p.write(q);
            }
        }
    });
}

#[test]
#[ignore = "needs Docker (bluenviron/mediamtx) and ffmpeg; run with --ignored"]
fn mediamtx_restarts() {
    let mtx = Mtx::start();
    let e = Arc::new({
        let e = Engine::builder().client_threads(1).build().unwrap();
        e.start().unwrap();
        e
    });
    let hub = Hub::default();
    // Sources: ffmpeg on "cam" (RTSP), our push of the sample on "pushed_rtsp" and
    // "pushed_rtmp".
    let mut ff = ffmpeg_publish(&format!("rtsp://{}/live/cam", mtx.rtsp));
    let stop = Arc::new(AtomicBool::new(false));
    feed(&hub, "src", stop.clone());
    let mut rc = RtspClientConfig::default();
    rc.reconnect = Some(reconnect(&e));
    let mut mc = RtmpClientConfig::default();
    mc.reconnect = Some(reconnect(&e));
    let push_rtsp = rtsp::push(
        &e,
        &format!("rtsp://{}/live/pushed_rtsp", mtx.rtsp),
        &hub,
        "src",
        rc.clone(),
    )
    .expect("rtsp push");
    let push_rtmp = rtmp::push(
        &e,
        &format!("rtmp://{}/live/pushed_rtmp", mtx.rtmp),
        &hub,
        "src",
        mc.clone(),
    )
    .expect("rtmp push");
    // Pulls (mediamtx offers a path once it has seen its tracks: the first tries may fail,
    // which reconnects cure for RTMP; the RTSP pull's first session must succeed, so wait).
    let (rtsp_heard, _s1) = subscribe(&hub, "cam_rtsp");
    let (rtmp_heard, _s2) = subscribe(&hub, "cam_rtmp");
    let (back_heard, _s3) = subscribe(&hub, "back_rtsp");
    let (back2_heard, _s4) = subscribe(&hub, "back_rtmp");
    let cam = format!("rtsp://{}/live/cam", mtx.rtsp);
    let mut pull_rtsp = None;
    wait_for("cam published", 30, || {
        pull_rtsp = rtsp::pull(&e, &cam, &hub, "cam_rtsp", rc.clone()).ok();
        pull_rtsp.is_some()
    });
    let pull_rtsp = pull_rtsp.unwrap();
    let pull_rtmp = rtmp::pull(
        &e,
        &format!("rtmp://{}/live/cam", mtx.rtmp),
        &hub,
        "cam_rtmp",
        mc.clone(),
    )
    .expect("rtmp pull");
    let mut back_rtsp = None;
    wait_for("pushed_rtsp available", 30, || {
        back_rtsp = rtsp::pull(
            &e,
            &format!("rtsp://{}/live/pushed_rtsp", mtx.rtsp),
            &hub,
            "back_rtsp",
            rc.clone(),
        )
        .ok();
        back_rtsp.is_some()
    });
    let back_rtsp = back_rtsp.unwrap();
    let back_rtmp = rtmp::pull(
        &e,
        &format!("rtmp://{}/live/pushed_rtmp", mtx.rtmp),
        &hub,
        "back_rtmp",
        mc,
    )
    .expect("rtmp pull");
    let all = [&rtsp_heard, &rtmp_heard, &back_heard, &back2_heard];
    wait_for("media on every path", 30, || {
        all.iter().all(|h| h.packets() > 100)
    });
    // The tracks are in step in the RTSP pull, as ffmpeg sent them.
    let skew = rtsp_heard.skew(20);
    eprintln!("rtsp pull: audio vs video skew {} ms", skew / MILLISECOND);
    assert!(skew.abs() < 250 * MILLISECOND, "skew {skew}");

    // Restart: every session drops; ffmpeg is restarted, our pushes reconnect, and so do the
    // pulls, which keep their paths.
    for round in 1..=2usize {
        let before: Vec<usize> = all.iter().map(|h| h.packets()).collect();
        let _ = ff.kill();
        let _ = ff.wait();
        mtx.restart(round);
        ff = ffmpeg_publish(&cam);
        for p in ["cam_rtsp", "cam_rtmp", "back_rtsp", "back_rtmp"] {
            assert!(
                hub.reserve(p, PeerInfo::default()).is_err(),
                "{p} was released"
            );
        }
        wait_for("republished", 60, || {
            all.iter()
                .zip(&before)
                .all(|(h, b)| h.tracks() > round && h.packets() > b + 100)
        });
        assert!(push_rtsp.reconnects() >= round as u64 && push_rtmp.reconnects() >= round as u64);
        assert!(pull_rtsp.reconnects() >= round as u64 && pull_rtmp.reconnects() >= round as u64);
        assert!(back_rtsp.reconnects() >= 1 && back_rtmp.reconnects() >= 1);
        let at = rtsp_heard.packets();
        wait_for("more media", 10, || rtsp_heard.packets() > at + 150);
        let skew = rtsp_heard.skew(at);
        eprintln!(
            "round {round}: audio vs video skew {} ms",
            skew / MILLISECOND
        );
        assert!(skew.abs() < 250 * MILLISECOND, "skew {skew}");
    }
    for c in [&pull_rtsp, &back_rtsp, &push_rtsp] {
        c.close();
        assert!(c.is_closed() && c.error().is_none());
    }
    for c in [&pull_rtmp, &back_rtmp, &push_rtmp] {
        c.close();
        assert!(c.is_closed());
    }
    for p in ["cam_rtsp", "cam_rtmp", "back_rtsp", "back_rtmp"] {
        drop(hub.reserve(p, PeerInfo::default()).expect("released"));
    }
    stop.store(true, Ordering::Relaxed);
    let _ = ff.kill();
    let _ = ff.wait();
    e.shutdown();
}
