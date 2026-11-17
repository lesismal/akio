//! The RTSP client against the RTSP server of this crate over loopback: pull (PLAY) and push
//! (RECORD), over TCP and UDP, with the sample files fed into a hub; Digest authentication;
//! TEARDOWN on close.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use only::{Engine, Listener};
use only_media::{
    Codec, Hub, Packet, PeerInfo, Sink, SubscribeOptions, Tracks,
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
    assert_eq!(
        push.error(),
        Some(ClientError::Hub(only_media::HubError::Unpublished))
    );
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
