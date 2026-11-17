//! The client's later features on loopback: v2 and hybrid torrents (BEP 52; piece layers
//! fetched with hash requests for v2 magnet links, a hybrid torrent reached under either hash),
//! web seeds (BEP 19) from an only-http file server, Local Service Discovery (BEP 14), IPv6
//! (a dual-stack client, the DHT over IPv6), rate limits and seed limits.

use std::net::{Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use only::{Engine, Listener};
use only_bittorrent::client::{
    AddOptions, Client, ClientConfig, MemoryStorage, RateLimits, SeedLimits, Torrent, TorrentEvent,
    TorrentStatus,
};
use only_bittorrent::metainfo::{Builder, Info, MetaInfo, TorrentVersion};
use only_bittorrent::mse::Policy;

fn data(n: usize, seed: u32) -> Vec<u8> {
    let mut x = seed | 1;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}

fn cfg() -> ClientConfig {
    let mut c = ClientConfig::default();
    c.listen = "127.0.0.1:0".parse().unwrap();
    c.encryption = Policy::Prefer;
    c.dht = false;
    c.lsd = false;
    c.tracker_timeout = Duration::from_millis(500);
    c
}

fn files() -> Vec<(Vec<String>, Vec<u8>)> {
    vec![
        (vec!["big.bin".to_owned()], data(1_300_000, 3)),
        (vec!["empty".to_owned()], Vec::new()),
        (
            vec!["sub".to_owned(), "small.txt".to_owned()],
            data(9_000, 5),
        ),
        (
            vec!["sub".to_owned(), "mid.bin".to_owned()],
            data(200_000, 9),
        ),
    ]
}

/// The piece-space bytes of `info` (files, with zeros for padding).
fn piece_space(info: &Info, files: &[(Vec<String>, Vec<u8>)]) -> Vec<u8> {
    let mut out = vec![0u8; info.total_length as usize];
    for f in info.files.iter().filter(|f| !f.padding) {
        let path = if info.single_file {
            &files[0].0
        } else {
            &f.path
        };
        let (_, d) = files.iter().find(|(p, _)| p == path).unwrap();
        out[f.offset as usize..f.offset as usize + d.len()].copy_from_slice(d);
    }
    out
}

fn seed(mi: &MetaInfo, payload: &[u8], c: ClientConfig) -> (Client, Torrent) {
    let client = Client::new(c).unwrap();
    let mut o = AddOptions::default();
    o.storage = Some(Arc::new(MemoryStorage::with_data(payload.to_vec())));
    let t = client.add_torrent(mi.clone(), o).unwrap();
    assert!(t.wait_complete(Duration::from_secs(10)), "seeder check");
    (client, t)
}

fn leech_opts(mi: &MetaInfo, peers: Vec<SocketAddr>) -> (AddOptions, Arc<MemoryStorage>) {
    let store = Arc::new(MemoryStorage::new(mi.info.total_length));
    let mut o = AddOptions::default();
    o.storage = Some(store.clone());
    o.peers = peers;
    (o, store)
}

fn v2_torrent(v: TorrentVersion) -> (MetaInfo, Vec<u8>) {
    let f = files();
    let mi = Builder::new("v2t")
        .piece_length(32 * 1024)
        .version(v)
        .build_files(&f)
        .unwrap();
    let payload = piece_space(&mi.info, &f);
    (mi, payload)
}

#[test]
fn v2_and_hybrid_torrents_by_metainfo() {
    for v in [TorrentVersion::V2, TorrentVersion::Hybrid] {
        let (mi, payload) = v2_torrent(v);
        let (s, _) = seed(&mi, &payload, cfg());
        let c = Client::new(cfg()).unwrap();
        let (o, store) = leech_opts(&mi, vec![s.listen_addr()]);
        let t = c.add_torrent(mi.clone(), o).unwrap();
        assert!(
            t.wait_complete(Duration::from_secs(30)),
            "{v:?} {:?}",
            t.stats()
        );
        assert!(store.snapshot() == payload, "{v:?}");
        assert_eq!(t.stats().hash_fails, 0);
        c.close();
        s.close();
    }
}

#[test]
fn v2_magnet_fetches_piece_layers() {
    let (mi, payload) = v2_torrent(TorrentVersion::V2);
    let (s, _) = seed(&mi, &payload, cfg());
    let c = Client::new(cfg()).unwrap();
    let mut m = mi.magnet();
    m.peers.push(s.listen_addr());
    assert!(m.is_v2_only());
    let (o, store) = leech_opts(&mi, Vec::new());
    let t = c.add_magnet(&m.to_string(), o).unwrap();
    assert!(t.wait_metadata(Duration::from_secs(20)), "{:?}", t.stats());
    assert!(t.wait_complete(Duration::from_secs(30)), "{:?}", t.stats());
    assert!(store.snapshot() == payload);
    // The layers came from the seeder's hash answers.
    assert_eq!(t.piece_layers(), mi.piece_layers);
    assert_eq!(t.metainfo().unwrap().to_bytes(), {
        let mut m2 = MetaInfo::from_info(mi.info.clone());
        m2.piece_layers = mi.piece_layers;
        m2.to_bytes()
    });
    c.close();
    s.close();
}

#[test]
fn hybrid_reached_under_either_hash() {
    let (mi, payload) = v2_torrent(TorrentVersion::Hybrid);
    let (s, _) = seed(&mi, &payload, cfg());
    let v2 = mi.info_hash_v2.unwrap();
    assert!(s.torrent(&v2.truncated()).is_some());
    // A v2-only link of a hybrid torrent: handshakes with the truncated v2 hash.
    let mut m = mi.magnet();
    m.info_hash = v2.truncated();
    m.peers.push(s.listen_addr());
    assert!(m.is_v2_only());
    let c = Client::new(cfg()).unwrap();
    let (o, store) = leech_opts(&mi, Vec::new());
    let t = c.add_magnet(&m.to_string(), o).unwrap();
    assert!(t.wait_complete(Duration::from_secs(30)), "{:?}", t.stats());
    assert!(store.snapshot() == payload);
    // Once the dictionary is known the v1 hash names the torrent too.
    assert!(c.torrent(&mi.info_hash).is_some());
    c.close();
    s.close();
}

/// An only-http file server for `dir` on loopback.
fn file_server(dir: &std::path::Path) -> (Arc<Engine>, SocketAddr) {
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);
    let engine = Arc::new(
        Engine::builder()
            .listen(
                Listener::tcp(addr)
                    .threads(1)
                    .serve(only_http::serve(only_http::files::Files::new(dir))),
            )
            .build()
            .unwrap(),
    );
    engine.start().unwrap();
    (engine, addr)
}

#[test]
fn web_seed_alone() {
    let dir = std::env::temp_dir().join(format!("only-bt-ws-{}", std::process::id()));
    let f = files();
    for (path, d) in &f {
        let mut p = dir.join("www").join("wst");
        p.extend(path);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, d).unwrap();
    }
    let (_e, addr) = file_server(&dir.join("www"));
    for v in [
        TorrentVersion::V1,
        TorrentVersion::Hybrid,
        TorrentVersion::V2,
    ] {
        let mi = Builder::new("wst")
            .piece_length(32 * 1024)
            .version(v)
            .web_seed(format!("http://{addr}/"))
            .build_files(&f)
            .unwrap();
        let payload = piece_space(&mi.info, &f);
        let c = Client::new(cfg()).unwrap();
        let (o, store) = leech_opts(&mi, Vec::new());
        let t = c.add_torrent(mi.clone(), o).unwrap();
        assert!(
            t.wait_complete(Duration::from_secs(30)),
            "{v:?} {:?}",
            t.stats()
        );
        assert!(store.snapshot() == payload, "{v:?}");
        c.close();
    }
    // A web seed that does not answer is retried with a backoff and reported.
    let mi = Builder::new("wst")
        .piece_length(32 * 1024)
        .web_seed("http://127.0.0.1:9/")
        .build_files(&f)
        .unwrap();
    let errors = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut c2 = cfg();
    let e2 = errors.clone();
    c2.on_event = Some(Arc::new(move |_, e| {
        if matches!(e, TorrentEvent::WebSeedError { .. }) {
            e2.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }));
    let c = Client::new(c2).unwrap();
    let (o, _) = leech_opts(&mi, Vec::new());
    let t = c.add_torrent(mi, o).unwrap();
    std::thread::sleep(Duration::from_secs(2));
    let n = errors.load(std::sync::atomic::Ordering::Relaxed);
    assert!((1..=3).contains(&n), "{n} errors in 2 s");
    assert_eq!(t.stats().pieces_have, 0);
    c.close();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rate_limits_hold() {
    let payload = data(1 << 20, 13);
    let mi = Builder::new("rl.bin")
        .piece_length(64 * 1024)
        .build_bytes(&payload)
        .unwrap();
    // Upload limited at the seeder (client-wide), download at the leecher (per torrent).
    for upload_side in [true, false] {
        let mut sc = cfg();
        if upload_side {
            sc.rate_limits = RateLimits::new(Some(256 * 1024), None);
        }
        let (s, _) = seed(&mi, &payload, sc);
        let c = Client::new(cfg()).unwrap();
        let (mut o, store) = leech_opts(&mi, vec![s.listen_addr()]);
        if !upload_side {
            o.rate_limits = RateLimits::new(None, Some(256 * 1024));
        }
        let start = Instant::now();
        let t = c.add_torrent(mi.clone(), o).unwrap();
        assert!(t.wait_complete(Duration::from_secs(30)), "{:?}", t.stats());
        let took = start.elapsed();
        assert!(store.snapshot() == payload);
        // 1 MiB at 256 KiB/s: about 4 s (the first fifth of a second is a burst).
        assert!(
            took >= Duration::from_millis(3000),
            "upload_side={upload_side}: {took:?}"
        );
        assert!(
            took < Duration::from_secs(12),
            "upload_side={upload_side}: {took:?}"
        );
        c.close();
        s.close();
    }
}

#[test]
fn seed_limits_pause() {
    let payload = data(512 * 1024, 17);
    let mi = Builder::new("sl.bin")
        .piece_length(64 * 1024)
        .build_bytes(&payload)
        .unwrap();
    // Ratio 1: a seeder that started complete stops once it uploaded the torrent's size.
    let mut sc = cfg();
    sc.seed_limits = SeedLimits::new(Some(1.0), None);
    let (s, st) = seed(&mi, &payload, sc);
    let c = Client::new(cfg()).unwrap();
    let (o, _) = leech_opts(&mi, vec![s.listen_addr()]);
    let t = c.add_torrent(mi.clone(), o).unwrap();
    assert!(t.wait_complete(Duration::from_secs(30)));
    let deadline = Instant::now() + Duration::from_secs(5);
    while st.stats().status != TorrentStatus::Paused && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(st.stats().status, TorrentStatus::Paused);
    assert!(st.stats().uploaded >= payload.len() as u64);
    c.close();
    s.close();
    // Time: a second of seeding.
    let mut sc = cfg();
    sc.seed_limits = SeedLimits::new(None, Some(Duration::from_secs(1)));
    let (s, st) = seed(&mi, &payload, sc);
    std::thread::sleep(Duration::from_millis(1500));
    assert_eq!(st.stats().status, TorrentStatus::Paused);
    assert!(st.stats().seeding_time >= Duration::from_secs(1));
    st.set_seed_limits(SeedLimits::default());
    st.resume();
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(st.stats().status, TorrentStatus::Seeding);
    s.close();
}

fn ipv6_loopback() -> bool {
    std::net::TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).is_ok()
}

#[test]
fn dual_stack_peers_and_dht6() {
    if !ipv6_loopback() {
        eprintln!("no IPv6 loopback: skipped");
        return;
    }
    let payload = data(600_000, 21);
    let mi = Builder::new("v6.bin")
        .piece_length(32 * 1024)
        .build_bytes(&payload)
        .unwrap();
    let mut sc = cfg();
    sc.listen = "[::]:0".parse().unwrap();
    sc.dht = true;
    let (s, _) = seed(&mi, &payload, sc);
    let port = s.listen_addr().port();
    // An IPv6 leecher and an IPv4 one reach the dual-stack seeder.
    for (ip, utp) in [
        ("::1", false),
        ("::1", true),
        ("127.0.0.1", false),
        ("127.0.0.1", true),
    ] {
        let mut lc = cfg();
        lc.listen = if ip == "::1" {
            "[::1]:0"
        } else {
            "127.0.0.1:0"
        }
        .parse()
        .unwrap();
        lc.utp = utp;
        let c = Client::new(lc).unwrap();
        let addr = SocketAddr::new(ip.parse().unwrap(), port);
        let (o, store) = leech_opts(&mi, vec![addr]);
        let t = c.add_torrent(mi.clone(), o).unwrap();
        assert!(
            t.wait_complete(Duration::from_secs(30)),
            "{ip} utp={utp} {:?}",
            t.stats()
        );
        assert!(store.snapshot() == payload);
        // The seeder sees the IPv4 peer as IPv4, not as ::ffff:127.0.0.1.
        let peers = s.torrent(&mi.info_hash).unwrap().peers();
        assert!(
            peers
                .iter()
                .all(|p| p.addr.ip().to_canonical() == p.addr.ip()),
            "{peers:?}"
        );
        c.close();
    }
    s.close();
    // The DHT over IPv6 alone: dual-stack nodes that only know each other at [::1]; the seeder
    // announces, the leecher finds it by magnet.
    let mut c0 = cfg();
    c0.listen = "[::]:0".parse().unwrap();
    c0.dht = true;
    let router = Client::new(c0.clone()).unwrap();
    let mut cs = c0;
    cs.dht_bootstrap = vec![SocketAddr::new(
        Ipv6Addr::LOCALHOST.into(),
        router.listen_addr().port(),
    )];
    let extra: Vec<Client> = (0..3).map(|_| Client::new(cs.clone()).unwrap()).collect();
    std::thread::sleep(Duration::from_millis(500));
    let (s, _) = seed(&mi, &payload, cs.clone());
    std::thread::sleep(Duration::from_secs(2));
    assert!(
        s.dht_nodes6() >= 2,
        "seeder knows {} IPv6 nodes",
        s.dht_nodes6()
    );
    let c = Client::new(cs).unwrap();
    let (o, store) = leech_opts(&mi, Vec::new());
    let t = c.add_magnet(&mi.magnet().to_string(), o).unwrap();
    assert!(t.wait_complete(Duration::from_secs(60)), "{:?}", t.stats());
    assert!(store.snapshot() == payload);
    assert!(
        t.peers().iter().all(|p| p.addr.is_ipv6()),
        "{:?}",
        t.peers()
    );
    c.close();
    s.close();
    for e in extra {
        e.close();
    }
    router.close();
}

#[test]
fn lsd_finds_the_seeder() {
    let payload = data(300_000, 23);
    let mi = Builder::new("lsd.bin")
        .piece_length(32 * 1024)
        .build_bytes(&payload)
        .unwrap();
    // Announcements come from the host's LAN address: listen on every address.
    let mut sc = cfg();
    sc.lsd = true;
    sc.listen = "0.0.0.0:0".parse().unwrap();
    let (s, _) = seed(&mi, &payload, sc);
    let mut lc = cfg();
    lc.lsd = true;
    lc.listen = "0.0.0.0:0".parse().unwrap();
    let c = Client::new(lc).unwrap();
    let (o, store) = leech_opts(&mi, Vec::new());
    let t = c.add_torrent(mi, o).unwrap();
    if !t.wait_complete(Duration::from_secs(20)) {
        // Hosts without a multicast route (some containers) cannot run LSD.
        let probe = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        if probe
            .send_to(b"x", only_bittorrent::lsd::MULTICAST_V4)
            .is_err()
        {
            eprintln!("no multicast route: skipped");
            return;
        }
        panic!("LSD did not find the seeder: {:?}", t.stats());
    }
    assert!(store.snapshot() == payload);
    c.close();
    s.close();
}
