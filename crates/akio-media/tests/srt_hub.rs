//! SRT end to end on a real `akio` engine over loopback UDP: a caller publishes MPEG-TS into the
//! hub, players read it back, push relays a hub stream, pull ingests one, and the server
//! rejects what it should.

use std::{
    sync::{Arc, Mutex, mpsc},
    time::{Duration, Instant},
};

use akio::{Engine, Listener};
use akio_media::{
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

/// Connections are bounded by default (1024); at the limit a new caller is rejected with
/// OVERLOAD, and a slot frees when one leaves.
#[test]
fn max_conns_has_a_safe_default_and_rejects_over_it() {
    assert_eq!(SrtConfig::default().max_conns, 1024);
    let hub = Hub::default();
    let mut cfg = SrtConfig::default().play_wait(Duration::from_secs(5));
    cfg.max_conns = 1;
    let (e, srv) = engine(&hub, cfg);
    let addr = e.local_addrs()[0];
    let (c1, _, _closed1) = collector();
    let first = srt::dial(&e, addr, Config::default().stream_id("live/x"), c1).unwrap();
    wait("first connected", || first.is_connected());
    let (c2, _, closed2) = collector();
    let _second = srt::dial(&e, addr, Config::default().stream_id("live/x"), c2).unwrap();
    assert_eq!(
        closed2.recv_timeout(Duration::from_secs(5)).unwrap(),
        Some(SrtError::Rejected(RejectReason::OVERLOAD))
    );
    first.close();
    wait("first gone", || srv.connections() == 0);
    let (c3, _, _closed3) = collector();
    let third = srt::dial(&e, addr, Config::default().stream_id("live/x"), c3).unwrap();
    wait("third connected", || third.is_connected());
    e.shutdown();
    e.wait();
}

/// A configuration whose peer would wait 30 s before taking a silent session as gone.
fn patient() -> Config {
    let mut c = Config::default().stream_id("#!::r=live/q,m=publish");
    c.peer_idle_timeout = Duration::from_secs(30);
    c
}

fn udp_client_engine() -> Arc<Engine> {
    let e = Engine::builder().udp_client_threads(1).build().unwrap();
    e.start().unwrap();
    Arc::new(e)
}

/// Follow-up of akit's A301: a caller's engine shutting down sends SHUTDOWN, so the server's
/// session ends at once rather than at its 30 s peer idle timeout, and the caller's handler
/// hears a local close (no error) rather than a transport error.
#[test]
fn a_callers_engine_shutdown_reaches_the_server() {
    let hub = Hub::default();
    let mut sc = SrtConfig::default();
    sc.peer_idle_timeout = Duration::from_secs(30);
    let (e_srv, srv) = engine(&hub, sc);
    let addr = e_srv.local_addrs()[0];
    let e = udp_client_engine();
    let (c, _, closed) = collector();
    let s = srt::dial(&e, addr, patient(), c).unwrap();
    wait("connected", || s.is_connected() && srv.connections() == 1);
    e.shutdown();
    e.wait();
    assert_eq!(closed.recv_timeout(Duration::from_secs(5)).unwrap(), None);
    let t0 = Instant::now();
    wait("the server's session ended", || srv.connections() == 0);
    assert!(t0.elapsed() < Duration::from_secs(10), "{:?}", t0.elapsed());
}

/// The server's engine shutting down sends SHUTDOWN to its callers: a caller hears
/// `PeerClosed` at once rather than `PeerIdle` after its 30 s timeout.
#[test]
fn a_servers_engine_shutdown_reaches_its_callers() {
    let hub = Hub::default();
    let (e_srv, srv) = engine(&hub, SrtConfig::default());
    let addr = e_srv.local_addrs()[0];
    let e = udp_client_engine();
    let (c, _, closed) = collector();
    let s = srt::dial(&e, addr, patient(), c).unwrap();
    wait("connected", || s.is_connected() && srv.connections() == 1);
    e_srv.shutdown();
    e_srv.wait();
    assert_eq!(
        closed.recv_timeout(Duration::from_secs(10)).unwrap(),
        Some(SrtError::PeerClosed)
    );
    assert!(!s.is_connected());
    e.shutdown();
}

/// A rendezvous side's engine shutting down sends SHUTDOWN: the other side hears
/// `PeerClosed` at once rather than `PeerIdle` after its 30 s timeout.
#[test]
fn a_rendezvous_engine_shutdown_reaches_the_peer() {
    let port = || {
        std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
    };
    let (a, b) = (port(), port());
    let (e1, e2) = (udp_client_engine(), udp_client_engine());
    let mut cfg = Config::default();
    cfg.peer_idle_timeout = Duration::from_secs(30);
    let (c1, _, closed1) = collector();
    let (c2, _, closed2) = collector();
    let s1 = srt::rendezvous(&e1, a, b, cfg.clone(), c1).unwrap();
    let s2 = srt::rendezvous(&e2, b, a, cfg, c2).unwrap();
    wait("rendezvous", || s1.is_connected() && s2.is_connected());
    e1.shutdown();
    e1.wait();
    assert_eq!(closed1.recv_timeout(Duration::from_secs(5)).unwrap(), None);
    assert_eq!(
        closed2.recv_timeout(Duration::from_secs(10)).unwrap(),
        Some(SrtError::PeerClosed)
    );
    e2.shutdown();
}
