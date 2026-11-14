//! SRT end to end on a real `only` engine over loopback UDP: a caller publishes MPEG-TS into the
//! hub, players read it back, push relays a hub stream, pull ingests one, and the server
//! rejects what it should.

use std::{
    sync::{Arc, Mutex, mpsc},
    time::{Duration, Instant},
};

use only::{Engine, Listener};
use only_media::{
    Codec, Hub,
    mpegts::demux::{Demuxer, Event as TsEvent},
    srt::{self, Config, RejectReason, SrtConfig, SrtError, SrtHandler, SrtServer, SrtSession},
};

const TS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/h264_aac.ts");

struct Collect {
    data: Arc<Mutex<Vec<u8>>>,
    closed: mpsc::Sender<Option<SrtError>>,
}

impl SrtHandler for Collect {
    fn on_data(&mut self, data: Vec<u8>) {
        self.data.lock().unwrap().extend_from_slice(&data);
    }
    fn on_close(&mut self, err: Option<SrtError>) {
        let _ = self.closed.send(err);
    }
}

type Collected = (
    Collect,
    Arc<Mutex<Vec<u8>>>,
    mpsc::Receiver<Option<SrtError>>,
);

fn collector() -> Collected {
    let data = Arc::new(Mutex::new(Vec::new()));
    let (tx, rx) = mpsc::channel();
    (
        Collect {
            data: data.clone(),
            closed: tx,
        },
        data,
        rx,
    )
}

fn wait(what: &str, mut f: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(10);
    while !f() {
        assert!(Instant::now() < end, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn engine(hub: &Hub, cfg: SrtConfig) -> (Arc<Engine>, SrtServer) {
    let srv = SrtServer::new(hub.clone(), cfg);
    let e = Engine::builder()
        .listen(Listener::udp("127.0.0.1:0".parse().unwrap()).serve(srv.clone()))
        .udp_client_threads(1)
        .build()
        .unwrap();
    e.start().unwrap();
    (Arc::new(e), srv)
}

/// Sends the sample TS file paced over ~1 s so the hub sees it as live.
fn publish_file(s: &SrtSession) {
    wait("publisher connected", || s.is_connected());
    let ts = std::fs::read(TS).unwrap();
    for (i, chunk) in ts.chunks(1316).enumerate() {
        s.send(chunk).unwrap();
        if i % 4 == 0 {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

fn demux(data: &[u8]) -> (Vec<Codec>, usize) {
    let mut d = Demuxer::new();
    let mut codecs = Vec::new();
    let mut n = 0;
    let _ = d.feed(data, &mut |e| match e {
        TsEvent::Tracks(t) => codecs = t.iter().map(|t| t.codec).collect(),
        TsEvent::Packet(_) => n += 1,
        _ => {}
    });
    (codecs, n)
}

#[test]
fn publish_and_play_through_the_hub() {
    let hub = Hub::default();
    let (e, srv) = engine(&hub, SrtConfig::default().play_wait(Duration::from_secs(5)));
    let addr = e.local_addrs()[0];

    // A player that connects first waits for the publisher.
    let (c, played, _closed) = collector();
    let player = srt::dial(&e, addr, Config::default().stream_id("live/s"), c).unwrap();

    let (pc, _, _) = collector();
    let publisher = srt::dial(
        &e,
        addr,
        Config::default().stream_id("#!::r=live/s,m=publish"),
        pc,
    )
    .unwrap();
    publish_file(&publisher);
    wait("stream live", || {
        hub.stream_info("live/s")
            .is_some_and(|s| s.publishing && s.packets_in > 50)
    });
    let info = hub.stream_info("live/s").unwrap();
    assert_eq!(info.tracks.len(), 2);
    assert_eq!(info.publisher.protocol, "srt");

    // A second publisher of the same path is rejected in the handshake.
    let (pc2, _, closed2) = collector();
    let _p2 = srt::dial(
        &e,
        addr,
        Config::default().stream_id("#!::r=live/s,m=publish"),
        pc2,
    )
    .unwrap();
    assert_eq!(
        closed2.recv_timeout(Duration::from_secs(5)).unwrap(),
        Some(SrtError::Rejected(RejectReason::CONFLICT))
    );

    // A late player starts from the GOP cache.
    let (c2, late, _) = collector();
    let _late = srt::dial(&e, addr, Config::default().stream_id("#!::r=live/s"), c2).unwrap();
    wait("players got media", || {
        let (a, n1) = demux(&played.lock().unwrap());
        let (b, n2) = demux(&late.lock().unwrap());
        a == [Codec::H264, Codec::Aac] && b == a && n1 > 20 && n2 > 5
    });
    assert!(player.is_connected());
    assert_eq!(srv.connections(), 3);

    // Unknown streams without play_wait are refused (fresh server).
    let hub2 = Hub::default();
    let (e2, _) = engine(&hub2, SrtConfig::default());
    let (c3, _, closed3) = collector();
    let _x = srt::dial(
        &e2,
        e2.local_addrs()[0],
        Config::default().stream_id("none"),
        c3,
    )
    .unwrap();
    assert_eq!(
        closed3.recv_timeout(Duration::from_secs(5)).unwrap(),
        Some(SrtError::Rejected(RejectReason::NOT_FOUND))
    );

    publisher.close();
    wait("unpublished", || {
        hub.stream_info("live/s").is_none_or(|s| !s.publishing)
    });
}

#[test]
fn push_pull_and_encryption() {
    let hub = Hub::default();
    let (e, _) = engine(&hub, SrtConfig::default().passphrase("0123456789secret"));
    let addr = e.local_addrs()[0];
    // Publish "src" encrypted.
    let (pc, _, _) = collector();
    let p = srt::dial(
        &e,
        addr,
        Config::default()
            .stream_id("#!::r=live/src,m=publish")
            .passphrase("0123456789secret"),
        pc,
    )
    .unwrap();
    publish_file(&p);
    wait("src live", || {
        hub.stream_info("live/src").is_some_and(|s| s.publishing)
    });

    // Push src back to the same server as "dst".
    let _push = srt::push(
        &e,
        addr,
        Config::default()
            .stream_id("#!::r=live/dst,m=publish")
            .passphrase("0123456789secret"),
        &hub,
        "live/src",
    )
    .unwrap();
    wait("dst live", || {
        hub.stream_info("live/dst")
            .is_some_and(|s| s.publishing && s.tracks.len() == 2)
    });

    // Pull dst into "copy".
    let _pull = srt::pull(
        &e,
        addr,
        Config::default()
            .stream_id("#!::r=live/dst,m=request")
            .passphrase("0123456789secret"),
        &hub,
        "live/copy",
    )
    .unwrap();
    wait("copy live", || {
        hub.stream_info("live/copy")
            .is_some_and(|s| s.publishing && s.packets_in > 0)
    });

    // A wrong passphrase is rejected.
    let (c, _, closed) = collector();
    let _bad = srt::dial(
        &e,
        addr,
        Config::default()
            .stream_id("live/src")
            .passphrase("the wrong passphrase"),
        c,
    )
    .unwrap();
    assert_eq!(
        closed.recv_timeout(Duration::from_secs(5)).unwrap(),
        Some(SrtError::Rejected(RejectReason::BAD_SECRET))
    );
}
