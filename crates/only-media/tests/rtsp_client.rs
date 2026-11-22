//! The RTSP client against the RTSP server of this crate over loopback: pull (PLAY) and push
//! (RECORD), over TCP and UDP, with the sample files fed into a hub; Digest authentication;
//! TEARDOWN on close; reconnecting to a server that goes away and comes back on the same port
//! (a killable TCP forwarder in between; the pulled path kept, the new session's tracks
//! republished).

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use only::{Engine, Listener};
use only_media::{
    Codec, Hub, HubError, Packet, PeerInfo, Reconnect, Sink, SubscribeOptions, Tracks,
    av::MILLISECOND,
    flv::{Decoder, Demuxer, Event},
    mpegts,
    rtsp::{
        RtspConfig, RtspServer,
        client::{self, ClientError, RtspClientConfig, RtspTransport},
    },
};

const DATA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/");

/// The tracks and packets of a sample file.
fn sample(name: &str) -> (Tracks, Vec<Packet>) {
    let bytes = std::fs::read(format!("{DATA}{name}")).unwrap();
    let mut tracks = None;
    let mut pkts = Vec::new();
    if name.ends_with(".flv") {
        let mut dec = Decoder::new();
        for t in Demuxer::new().feed(&bytes).unwrap() {
            for e in dec.write(t.tag_type, t.ts, &t.body) {
                match e {
                    Event::Tracks(t) => tracks = Some(t),
                    Event::Packet(p) => pkts.push(p),
                    _ => {}
                }
            }
        }
    } else {
        let mut d = mpegts::demux::Demuxer::new();
        let mut emit = |e| match e {
            mpegts::demux::Event::Tracks(t) => tracks = Some(t),
            mpegts::demux::Event::Packet(p) => pkts.push(p),
            _ => {}
        };
        d.feed(&bytes, &mut emit).unwrap();
        d.flush(&mut emit);
    }
    (tracks.unwrap(), pkts)
}

/// Publishes `name` at `path` in real time, looped, until the returned flag is set.
fn feed(hub: &Hub, path: &str, name: &str) -> (Tracks, Arc<AtomicBool>) {
    let (tracks, pkts) = sample(name);
    let p = hub
        .publish(path, tracks.clone(), PeerInfo::default())
        .unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let s = stop.clone();
    std::thread::spawn(move || {
        let span = pkts.iter().map(|p| p.dts).max().unwrap_or(0) + 40 * MILLISECOND;
        let start = Instant::now();
        for round in 0.. {
            for pkt in &pkts {
                if s.load(Ordering::Relaxed) {
                    return;
                }
                let off = round * span;
                let at = Duration::from_nanos((pkt.dts + off).max(0) as u64);
                if let Some(d) = at.checked_sub(start.elapsed()) {
                    std::thread::sleep(d);
                }
                let q = Packet::new(
                    pkt.track,
                    pkt.dts + off,
                    pkt.pts + off,
                    pkt.keyframe,
                    pkt.data.clone(),
                );
                p.write(q);
            }
        }
    });
    (tracks, stop)
}

fn start(cfg: RtspConfig) -> (Hub, Engine, std::net::SocketAddr) {
    let hub = Hub::default();
    let srv = RtspServer::new(hub.clone(), cfg);
    srv.listen_udp("127.0.0.1:0".parse().unwrap()).unwrap();
    let engine = Engine::builder()
        .listen(Listener::tcp("127.0.0.1:0".parse().unwrap()).serve(srv))
        .client_threads(1)
        .udp_client_threads(1)
        .build()
        .unwrap();
    engine.start().unwrap();
    let addr = engine.local_addrs()[0];
    (hub, engine, addr)
}

/// Counts what a hub stream delivers, per track.
struct Count(Arc<Vec<AtomicU64>>);

impl Sink for Count {
    fn on_tracks(&mut self, _t: &Tracks) {}
    fn on_packet(&mut self, p: &Arc<Packet>) {
        if let Some(c) = self.0.get(p.track) {
            c.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn wait(what: &str, secs: u64, mut f: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while !f() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn codecs(t: &Tracks) -> Vec<Codec> {
    t.iter().map(|t| t.codec).collect()
}

/// Waits for `path` to be live with the codecs of `want`, then checks that every track
/// carries packets over a second.
fn check_live(hub: &Hub, path: &str, want: &Tracks) {
    wait(&format!("{path} live"), 10, || {
        hub.stream_info(path).is_some_and(|i| i.publishing)
    });
    let info = hub.stream_info(path).unwrap();
    assert_eq!(codecs(&info.tracks), codecs(want), "{path}");
    let counts: Arc<Vec<AtomicU64>> =
        Arc::new((0..want.len()).map(|_| AtomicU64::new(0)).collect());
    let _sub = hub
        .subscribe(
            path,
            Count(counts.clone()),
            SubscribeOptions::new(PeerInfo::default()),
        )
        .unwrap();
    wait(&format!("{path} packets"), 10, || {
        counts.iter().all(|c| c.load(Ordering::Relaxed) >= 10)
    });
}

fn cfg(t: RtspTransport) -> RtspClientConfig {
    let mut c = RtspClientConfig::default();
    c.transport = t;
    c
}

fn pull_and_push(file: &str, t: RtspTransport) {
    let (hub, engine, addr) = start(RtspConfig::default());
    let (tracks, stop) = feed(&hub, "src", file);
    wait("src live", 5, || {
        hub.stream_info("src").is_some_and(|i| i.publishing)
    });

    // PLAY rtsp://.../src into the hub at "pulled".
    let pulled = client::pull(
        &engine,
        &format!("rtsp://{addr}/src"),
        &hub,
        "pulled",
        cfg(t),
    )
    .unwrap();
    check_live(&hub, "pulled", &tracks);

    // RECORD "src" to rtsp://.../pushed (the server publishes it at "pushed").
    let pushed = client::push(
        &engine,
        &format!("rtsp://{addr}/pushed"),
        &hub,
        "src",
        cfg(t),
    )
    .unwrap();
    check_live(&hub, "pushed", &tracks);

    // A pushed copy of the pulled copy: both directions chain.
    let chained = client::push(
        &engine,
        &format!("rtsp://{addr}/chained"),
        &hub,
        "pulled",
        cfg(t),
    )
    .unwrap();
    check_live(&hub, "chained", &tracks);

    // Closing sends TEARDOWN: the server unpublishes, the pulled path is released.
    assert!(!pushed.is_closed() && pushed.error().is_none());
    pushed.close();
    assert!(pushed.is_closed() && pushed.error().is_none());
    wait("pushed unpublished", 5, || {
        !hub.stream_info("pushed").is_some_and(|i| i.publishing)
    });
    drop(chained);
    drop(pulled);
    wait("pulled unpublished", 5, || {
        !hub.stream_info("pulled").is_some_and(|i| i.publishing)
    });
    stop.store(true, Ordering::Relaxed);
    engine.shutdown();
}

#[test]
fn h264_aac_over_tcp() {
    pull_and_push("h264_aac.flv", RtspTransport::Tcp);
}

#[test]
fn h264_aac_over_udp() {
    pull_and_push("h264_aac.flv", RtspTransport::Udp);
}

#[test]
fn h265_aac_over_tcp() {
    pull_and_push("h265_aac.flv", RtspTransport::Tcp);
}

#[test]
fn h265_opus_over_udp() {
    pull_and_push("h265_opus.ts", RtspTransport::Udp);
}

#[test]
fn h265_opus_over_tcp() {
    pull_and_push("h265_opus.ts", RtspTransport::Tcp);
}

#[test]
fn digest_auth_and_refusals() {
    let mut rc = RtspConfig::default();
    rc.credentials = Some(Arc::new(|u: &str| {
        (u == "admin").then(|| "s3cr:t".to_owned())
    }));
    let (hub, engine, addr) = start(rc);
    let (tracks, stop) = feed(&hub, "src", "h264_aac.flv");
    wait("src live", 5, || {
        hub.stream_info("src").is_some_and(|i| i.publishing)
    });
    let ok = format!("rtsp://admin:s3cr%3At@{addr}/src");
    let c = client::pull(&engine, &ok, &hub, "pulled", cfg(RtspTransport::Tcp)).unwrap();
    check_live(&hub, "pulled", &tracks);
    drop(c);
    let p = client::push(
        &engine,
        &format!("rtsp://admin:s3cr%3At@{addr}/pushed"),
        &hub,
        "src",
        cfg(RtspTransport::Udp),
    )
    .unwrap();
    check_live(&hub, "pushed", &tracks);
    drop(p);

    let bad = format!("rtsp://admin:nope@{addr}/src");
    let r = client::pull(&engine, &bad, &hub, "x", RtspClientConfig::default());
    assert_eq!(r.unwrap_err(), ClientError::Unauthorized);
    let r = client::pull(
        &engine,
        &format!("rtsp://{addr}/src"),
        &hub,
        "x",
        RtspClientConfig::default(),
    );
    assert_eq!(r.unwrap_err(), ClientError::Unauthorized);
    let r = client::pull(
        &engine,
        &format!("rtsp://admin:s3cr%3At@{addr}/missing"),
        &hub,
        "x",
        RtspClientConfig::default(),
    );
    assert!(
        matches!(
            r,
            Err(ClientError::Status {
                method: "DESCRIBE",
                status: 404,
                ..
            })
        ),
        "{r:?}"
    );
    stop.store(true, Ordering::Relaxed);
    engine.shutdown();
}

/// The publisher leaving ends a push with the hub's reason; a pull whose source stops sending
/// ends with the media timeout.
#[test]
fn sessions_end_with_their_source() {
    let (hub, engine, addr) = start(RtspConfig::default());
    let (_, stop) = feed(&hub, "src", "h264_aac.flv");
    wait("src live", 5, || {
        hub.stream_info("src").is_some_and(|i| i.publishing)
    });
    let push = client::push(
        &engine,
        &format!("rtsp://{addr}/pushed"),
        &hub,
        "src",
        RtspClientConfig::default(),
    )
    .unwrap();
    let mut c = RtspClientConfig::default();
    c.idle_timeout = Duration::from_millis(500);
    let pull = client::pull(&engine, &format!("rtsp://{addr}/pushed"), &hub, "pulled", c).unwrap();
    wait("pulled live", 10, || {
        hub.stream_info("pulled").is_some_and(|i| i.publishing)
    });
    // The feeder ends and drops its publisher: "src" is unpublished.
    stop.store(true, Ordering::Relaxed);
    wait("push ended", 10, || push.is_closed());
    assert_eq!(push.error(), Some(ClientError::Hub(HubError::Unpublished)));
    wait("pull ended", 10, || pull.is_closed());
    assert!(
        matches!(
            pull.error(),
            Some(ClientError::Timeout("media") | ClientError::Closed)
        ),
        "{:?}",
        pull.error()
    );
    engine.shutdown();
}

// ---- interop: mediamtx and ffmpeg ---------------------------------------------------------

fn have(tool: &str) -> bool {
    std::process::Command::new(tool)
        .arg("-version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// A client-only engine (TCP dials and UDP sockets).
fn client_engine() -> Engine {
    let e = Engine::builder()
        .client_threads(1)
        .udp_client_threads(1)
        .build()
        .unwrap();
    e.start().unwrap();
    e
}

/// The codec names ffprobe reports for the RTSP URL `input` (read over TCP), sorted.
fn ffprobe(input: &str) -> Vec<String> {
    let out = std::process::Command::new("ffprobe")
        .args([
            "-hide_banner",
            "-loglevel",
            "error",
            "-rtsp_transport",
            "tcp",
        ])
        .args([
            "-show_entries",
            "stream=codec_name",
            "-of",
            "csv=p=0",
            input,
        ])
        .output()
        .expect("ffprobe");
    let mut v: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| l.trim().trim_end_matches(',').to_owned())
        .filter(|l| !l.is_empty())
        .collect();
    v.sort();
    v
}

/// ffprobe's names of `t`'s codecs, sorted.
fn ff_names(t: &Tracks) -> Vec<String> {
    let mut v: Vec<String> = t
        .iter()
        .map(|t| {
            match t.codec {
                Codec::H264 => "h264",
                Codec::H265 => "hevc",
                Codec::Aac => "aac",
                Codec::Opus => "opus",
                _ => "?",
            }
            .to_owned()
        })
        .collect();
    v.sort();
    v
}

/// The transports `var` lists (`tcp,udp` by default).
fn transports(var: &str) -> Vec<(RtspTransport, &'static str)> {
    let want = std::env::var(var).unwrap_or_else(|_| "tcp,udp".into());
    [(RtspTransport::Tcp, "tcp"), (RtspTransport::Udp, "udp")]
        .into_iter()
        .filter(|(_, n)| want.split(',').any(|w| w.trim() == *n))
        .collect()
}

/// mediamtx (`ONLY_MEDIAMTX=host:port` of its RTSP listener, as
/// `tools/interop/media/rtsp-client.sh` starts it): our client records each sample to it,
/// ffprobe (when installed) reads it back from mediamtx over TCP, and our client plays it back
/// into the hub. Transports from `ONLY_MEDIAMTX_TRANSPORTS` (default `tcp,udp`);
/// `ONLY_MEDIAMTX_HOLD=<seconds>` keeps both sessions that long (past mediamtx's 60 s session
/// timeout, to exercise the keep-alives) and checks they still carry media. Skipped without
/// `ONLY_MEDIAMTX`.
#[test]
fn mediamtx_record_and_play() {
    let Ok(mtx) = std::env::var("ONLY_MEDIAMTX") else {
        eprintln!("ONLY_MEDIAMTX not set: skipped (see tools/interop/media/rtsp-client.sh)");
        return;
    };
    let probe = have("ffprobe");
    let engine = client_engine();
    for file in ["h264_aac.flv", "h265_opus.ts"] {
        let hub = Hub::default();
        let (tracks, stop) = feed(&hub, "src", file);
        wait("src live", 5, || {
            hub.stream_info("src").is_some_and(|i| i.publishing)
        });
        for (t, name) in transports("ONLY_MEDIAMTX_TRANSPORTS") {
            let stem = file.split('.').next().unwrap();
            let url = format!("rtsp://{mtx}/only_{stem}_{name}");
            let push = client::push(&engine, &url, &hub, "src", cfg(t))
                .unwrap_or_else(|e| panic!("push {url} over {name}: {e}"));
            std::thread::sleep(Duration::from_millis(1500));
            if probe {
                let got = ffprobe(&url);
                assert_eq!(got, ff_names(&tracks), "ffprobe {url} (pushed over {name})");
                eprintln!("ffprobe {url} (pushed over {name}): {got:?}");
            }
            let back = format!("back_{name}");
            let pull = client::pull(&engine, &url, &hub, &back, cfg(t))
                .unwrap_or_else(|e| panic!("pull {url} over {name}: {e}"));
            check_live(&hub, &back, &tracks);
            let hold: u64 = std::env::var("ONLY_MEDIAMTX_HOLD")
                .ok()
                .and_then(|h| h.parse().ok())
                .unwrap_or(0);
            if hold > 0 {
                let before = hub.stream_info(&back).unwrap().packets_in;
                std::thread::sleep(Duration::from_secs(hold));
                let after = hub.stream_info(&back).map_or(0, |i| i.packets_in);
                assert!(after > before + 100, "{name}: {before} -> {after} packets");
                eprintln!("{file}: held {hold} s over {name}, {before} -> {after} packets");
            }
            eprintln!("{file}: pushed to and pulled from mediamtx over {name}");
            assert!(push.error().is_none(), "{:?}", push.error());
            assert!(pull.error().is_none(), "{:?}", pull.error());
            drop(pull);
            drop(push);
        }
        stop.store(true, Ordering::Relaxed);
    }
    engine.shutdown();
}

/// ffmpeg as the server of a record (`-rtsp_flags listen`): our client pushes each sample over
/// each transport (`ONLY_FFMPEG_TRANSPORTS`, default `tcp,udp`) and ffmpeg demuxes three
/// seconds of it into `framecrc` (codecs, timestamps and checksums of every packet): every
/// track must be there with its codec and packets. (ffmpeg's listen mode cannot `-c copy` into
/// Matroska or MPEG-TS, not even from ffmpeg's own push: its first packets carry no pts.)
/// Skipped without ffmpeg.
#[test]
fn ffmpeg_listen_receives_push() {
    if !have("ffmpeg") {
        eprintln!("ffmpeg not found: skipped");
        return;
    }
    let engine = client_engine();
    let dir = std::env::temp_dir().join(format!("only-rtsp-client-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for file in ["h264_aac.flv", "h265_opus.ts"] {
        let hub = Hub::default();
        let (tracks, stop) = feed(&hub, "src", file);
        wait("src live", 5, || {
            hub.stream_info("src").is_some_and(|i| i.publishing)
        });
        for (t, name) in transports("ONLY_FFMPEG_TRANSPORTS") {
            let port = std::net::TcpListener::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap()
                .port();
            let url = format!("rtsp://127.0.0.1:{port}/s");
            let out = dir.join(format!("{file}.{name}.crc"));
            let mut ff = std::process::Command::new("ffmpeg")
                .args(["-hide_banner", "-loglevel", "error", "-y"])
                .args(["-rtsp_flags", "listen", "-listen_timeout", "20", "-i", &url])
                .args(["-t", "3", "-c", "copy", "-f", "framecrc"])
                .arg(&out)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            let push = loop {
                match client::push(&engine, &url, &hub, "src", cfg(t)) {
                    Ok(p) => break p,
                    Err(ClientError::Connect(_)) if Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(200));
                    }
                    Err(e) => panic!("push to ffmpeg over {name}: {e}"),
                }
            };
            let deadline = Instant::now() + Duration::from_secs(20);
            let status = loop {
                if let Some(s) = ff.try_wait().unwrap() {
                    break s;
                }
                if Instant::now() > deadline {
                    let _ = ff.kill();
                    panic!("ffmpeg did not finish over {name}");
                }
                std::thread::sleep(Duration::from_millis(50));
            };
            let mut log = String::new();
            if let Some(mut e) = ff.stderr.take() {
                let _ = std::io::Read::read_to_string(&mut e, &mut log);
            }
            assert!(status.success(), "ffmpeg over {name}: {log}");
            let crc = std::fs::read_to_string(&out).unwrap();
            let mut got = Vec::new();
            for (i, _) in tracks.iter().enumerate() {
                let codec = crc
                    .lines()
                    .find_map(|l| l.strip_prefix(&format!("#codec_id {i}: ")))
                    .unwrap_or_else(|| panic!("{file} over {name}: no stream {i}: {log}"));
                let packets = crc
                    .lines()
                    .filter(|l| l.starts_with(&format!("{i},")))
                    .count();
                assert!(
                    packets >= 20,
                    "{file} over {name}: stream {i} has {packets} packets"
                );
                got.push(codec.trim().to_owned());
            }
            got.sort();
            assert_eq!(got, ff_names(&tracks), "{file} over {name}: {log}");
            eprintln!("{file}: ffmpeg received our push over {name}: {got:?}");
            drop(push);
        }
        stop.store(true, Ordering::Relaxed);
    }
    let _ = std::fs::remove_dir_all(&dir);
    engine.shutdown();
}

// ---- reconnecting ---------------------------------------------------------------------------

/// Counts the tracks announcements and packets a subscriber hears.
#[derive(Clone, Default)]
struct Heard(Arc<(AtomicU64, AtomicU64)>);

impl Sink for Heard {
    fn on_tracks(&mut self, _t: &Tracks) {
        self.0.0.fetch_add(1, Ordering::Relaxed);
    }
    fn on_packet(&mut self, _p: &Arc<Packet>) {
        self.0.1.fetch_add(1, Ordering::Relaxed);
    }
}

fn reconnecting(t: RtspTransport, e: &Arc<Engine>) -> RtspClientConfig {
    let mut c = cfg(t);
    c.idle_timeout = Duration::from_secs(2);
    c.reconnect = Some(
        Reconnect::new(e)
            .initial_delay(Duration::from_millis(100))
            .max_delay(Duration::from_millis(400)),
    );
    c
}

/// A TCP forwarder to `to` on `at` (port 0 picks one) whose connections can be cut at once,
/// standing for a server that goes away.
struct Proxy {
    addr: std::net::SocketAddr,
    stop: Arc<AtomicBool>,
    conns: Arc<std::sync::Mutex<Vec<std::net::TcpStream>>>,
}

impl Proxy {
    fn start(at: std::net::SocketAddr, to: std::net::SocketAddr) -> Proxy {
        use std::net::{TcpListener, TcpStream};
        let l = TcpListener::bind(at).unwrap();
        l.set_nonblocking(true).unwrap();
        let addr = l.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let conns = Arc::new(std::sync::Mutex::new(Vec::<TcpStream>::new()));
        let (s, c) = (stop.clone(), conns.clone());
        std::thread::spawn(move || {
            while !s.load(Ordering::Relaxed) {
                let Ok((a, _)) = l.accept() else {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                };
                a.set_nonblocking(false).unwrap();
                let Ok(b) = TcpStream::connect(to) else {
                    continue;
                };
                let mut g = c.lock().unwrap();
                for (mut from, mut into) in [
                    (a.try_clone().unwrap(), b.try_clone().unwrap()),
                    (b.try_clone().unwrap(), a.try_clone().unwrap()),
                ] {
                    std::thread::spawn(move || {
                        let _ = std::io::copy(&mut from, &mut into);
                        let _ = into.shutdown(std::net::Shutdown::Both);
                    });
                }
                g.extend([a, b]);
            }
        });
        Proxy { addr, stop, conns }
    }

    /// Stops listening and cuts every connection.
    fn kill(self) {
        self.stop.store(true, Ordering::Relaxed);
        for c in self.conns.lock().unwrap().drain(..) {
            let _ = c.shutdown(std::net::Shutdown::Both);
        }
        std::thread::sleep(Duration::from_millis(20)); // the listener goes with its thread
    }
}

/// A reconnecting pull: the server goes away (its connections cut, nothing listening) and
/// another comes back on the same port with other codecs; the client keeps the hub path and
/// the subscriber, plays again and republishes the new tracks; closing frees the path at once.
fn pull_reconnects(t: RtspTransport) {
    let (src_hub, src_engine, server) = start(RtspConfig::default());
    let (_, stop) = feed(&src_hub, "src", "h264_aac.flv");
    wait("src live", 5, || {
        src_hub.stream_info("src").is_some_and(|i| i.publishing)
    });
    let proxy = Proxy::start("127.0.0.1:0".parse().unwrap(), server);
    let addr = proxy.addr;
    let ce = Arc::new(client_engine());
    let hub = Hub::default();
    let url = format!("rtsp://{addr}/src");
    let pull = client::pull(&ce, &url, &hub, "dst", reconnecting(t, &ce)).unwrap();
    let heard = Heard::default();
    let opts = SubscribeOptions::new(PeerInfo::default()).wait(Duration::from_secs(10));
    let _sub = hub.subscribe("dst", heard.clone(), opts).unwrap();
    wait("packets", 10, || heard.0.1.load(Ordering::Relaxed) > 20);
    assert!(pull.is_live());
    // The server goes away.
    proxy.kill();
    stop.store(true, Ordering::Relaxed);
    src_engine.shutdown();
    wait("session over", 10, || !pull.is_live());
    std::thread::sleep(Duration::from_millis(600)); // a few tries fail meanwhile
    assert!(!pull.is_closed());
    assert!(pull.error().is_some());
    assert_eq!(
        hub.reserve("dst", PeerInfo::default()).unwrap_err(),
        HubError::StreamBusy
    );
    // Another server on the same port, with H.265.
    let (src_hub, src_engine, server) = start(RtspConfig::default());
    let (tracks, stop) = feed(&src_hub, "src", "h265_aac.flv");
    let proxy = Proxy::start(addr, server);
    wait("reconnected", 15, || {
        pull.reconnects() == 1 && pull.is_live()
    });
    let before = heard.0.1.load(Ordering::Relaxed);
    wait("republished", 10, || {
        heard.0.0.load(Ordering::Relaxed) == 2 && heard.0.1.load(Ordering::Relaxed) > before + 20
    });
    let info = hub.stream_info("dst").unwrap();
    assert_eq!(codecs(&info.tracks), codecs(&tracks));
    assert_eq!(info.subscribers, 1);
    assert!(pull.error().is_none());
    pull.close();
    assert!(pull.is_closed());
    drop(
        hub.reserve("dst", PeerInfo::default())
            .expect("free at once"),
    );
    stop.store(true, Ordering::Relaxed);
    proxy.kill();
    src_engine.shutdown();
    ce.shutdown();
}

#[test]
fn pull_reconnects_over_tcp() {
    pull_reconnects(RtspTransport::Tcp);
}

#[test]
fn pull_reconnects_over_udp() {
    pull_reconnects(RtspTransport::Udp);
}

/// A reconnecting push: the receiving server goes away (its connections cut, nothing
/// listening) and comes back on the same port; the push records to it again, from the cached
/// GOP.
#[test]
fn push_reconnects() {
    let hub = Hub::default();
    let (tracks, stop) = feed(&hub, "src", "h264_aac.flv");
    wait("src live", 5, || {
        hub.stream_info("src").is_some_and(|i| i.publishing)
    });
    let (dst_hub, dst_engine, server) = start(RtspConfig::default());
    let proxy = Proxy::start("127.0.0.1:0".parse().unwrap(), server);
    let addr = proxy.addr;
    let ce = Arc::new(client_engine());
    let url = format!("rtsp://{addr}/pushed");
    let push = client::push(
        &ce,
        &url,
        &hub,
        "src",
        reconnecting(RtspTransport::Tcp, &ce),
    )
    .unwrap();
    check_live(&dst_hub, "pushed", &tracks);
    proxy.kill();
    wait("session over", 10, || !push.is_live());
    std::thread::sleep(Duration::from_millis(600)); // a few tries fail meanwhile
    assert!(!push.is_closed());
    wait("server's session over", 10, || {
        dst_hub.stream_info("pushed").is_none_or(|i| !i.publishing)
    });
    let proxy = Proxy::start(addr, server);
    wait("reconnected", 15, || {
        push.reconnects() == 1 && push.is_live()
    });
    check_live(&dst_hub, "pushed", &tracks);
    // The source ending ends the push for good.
    stop.store(true, Ordering::Relaxed);
    wait("push over", 10, || push.is_closed());
    assert_eq!(push.error(), Some(ClientError::Hub(HubError::Unpublished)));
    proxy.kill();
    dst_engine.shutdown();
    ce.shutdown();
}

/// mediamtx redirecting (`ONLY_MEDIAMTX_REDIRECT=host:port`, a mediamtx whose path `moved`
/// is `source: redirect` to `rtsp://host:port/rsrc`, as `tools/interop/media/rtsp-redirect.sh`
/// starts it): our client records a sample to `rsrc`, then plays `moved`, which mediamtx
/// answers with `302` and the `rsrc` URL; the pull must follow it and carry every track.
/// Transports from `ONLY_MEDIAMTX_TRANSPORTS`; `ONLY_MEDIAMTX_HOLD=<seconds>` keeps the
/// sessions (the pull sending its RTCP receiver reports) and checks media still flows.
/// Skipped without `ONLY_MEDIAMTX_REDIRECT`.
#[test]
fn mediamtx_redirect() {
    let Ok(mtx) = std::env::var("ONLY_MEDIAMTX_REDIRECT") else {
        eprintln!("ONLY_MEDIAMTX_REDIRECT not set: skipped (see tools/interop/media/rtsp-redirect.sh)");
        return;
    };
    let engine = client_engine();
    let hub = Hub::default();
    let (tracks, stop) = feed(&hub, "src", "h264_aac.flv");
    wait("src live", 5, || {
        hub.stream_info("src").is_some_and(|i| i.publishing)
    });
    let hold: u64 = std::env::var("ONLY_MEDIAMTX_HOLD")
        .ok()
        .and_then(|h| h.parse().ok())
        .unwrap_or(0);
    for (t, name) in transports("ONLY_MEDIAMTX_TRANSPORTS") {
        let push = client::push(&engine, &format!("rtsp://{mtx}/rsrc"), &hub, "src", cfg(t))
            .unwrap_or_else(|e| panic!("push over {name}: {e}"));
        std::thread::sleep(Duration::from_millis(1500));
        let back = format!("moved_{name}");
        let pull = client::pull(&engine, &format!("rtsp://{mtx}/moved"), &hub, &back, cfg(t))
            .unwrap_or_else(|e| panic!("pull of the redirect over {name}: {e}"));
        check_live(&hub, &back, &tracks);
        if hold > 0 {
            let before = hub.stream_info(&back).unwrap().packets_in;
            std::thread::sleep(Duration::from_secs(hold));
            let after = hub.stream_info(&back).map_or(0, |i| i.packets_in);
            assert!(after > before + 100, "{name}: {before} -> {after} packets");
        }
        assert!(pull.error().is_none(), "{:?}", pull.error());
        eprintln!("pulled rtsp://{mtx}/moved over {name}: redirected to rsrc, live");
        drop(pull);
        drop(push);
        std::thread::sleep(Duration::from_millis(500));
    }
    stop.store(true, Ordering::Relaxed);
    engine.shutdown();
}

/// A server that moves (`ONLY_MOVING_SERVER=name:port`, a name the Docker network resolves,
/// as `tools/interop/media/rtsp-redirect.sh` runs it): our client records a sample to
/// `name/mv` and plays it back, both reconnecting; once both are live it prints `READY`, and
/// the script replaces the server with another one at another address under the same name.
/// Both clients must look the name up again, find the new server and carry media within
/// `ONLY_MOVING_WAIT` seconds (default 120). Transport from `ONLY_MEDIAMTX_TRANSPORTS` (the
/// first one). Skipped without `ONLY_MOVING_SERVER`.
#[test]
fn server_moves_to_another_address() {
    use std::io::Write as _;
    let Ok(srv) = std::env::var("ONLY_MOVING_SERVER") else {
        eprintln!("ONLY_MOVING_SERVER not set: skipped (see tools/interop/media/rtsp-redirect.sh)");
        return;
    };
    let (t, name) = transports("ONLY_MEDIAMTX_TRANSPORTS")[0];
    let engine = Arc::new(client_engine());
    let hub = Hub::default();
    let (tracks, stop) = feed(&hub, "src", "h264_aac.flv");
    wait("src live", 5, || {
        hub.stream_info("src").is_some_and(|i| i.publishing)
    });
    let url = format!("rtsp://{srv}/mv");
    let push = client::push(&engine, &url, &hub, "src", reconnecting(t, &engine)).unwrap();
    std::thread::sleep(Duration::from_millis(1500));
    let pull = client::pull(&engine, &url, &hub, "back", reconnecting(t, &engine)).unwrap();
    check_live(&hub, "back", &tracks);
    println!("READY ({name})");
    std::io::stdout().flush().unwrap();
    let secs = std::env::var("ONLY_MOVING_WAIT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(120);
    wait("both reconnected", secs, || {
        push.reconnects() >= 1 && pull.reconnects() >= 1 && push.is_live() && pull.is_live()
    });
    let before = hub.stream_info("back").map_or(0, |i| i.packets_in);
    wait("media from the new server", 30, || {
        hub.stream_info("back").is_some_and(|i| i.packets_in > before + 100)
    });
    println!(
        "MOVED ({name}): push {} and pull {} reconnects, last errors {:?} / {:?}",
        push.reconnects(),
        pull.reconnects(),
        push.error(),
        pull.error()
    );
    drop(pull);
    drop(push);
    stop.store(true, Ordering::Relaxed);
    engine.shutdown();
}
