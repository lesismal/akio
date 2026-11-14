//! Local swarms on loopback: a flash seeder and flash leechers over TCP and uTP, with and
//! without MSE, peers found through HTTP and UDP trackers, magnet links (metadata exchange),
//! the DHT and PEX.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use flash::{Engine, Listener};
use flash_bittorrent::client::{AddOptions, Client, ClientConfig, MemoryStorage, TorrentStatus};
use flash_bittorrent::metainfo::{Builder, MetaInfo};
use flash_bittorrent::mse::Policy;
use flash_bittorrent::tracker::{TrackerConfig, TrackerServer};

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

fn tracker() -> (TrackerServer, Arc<Engine>, SocketAddr) {
    let t = TrackerServer::new(TrackerConfig::default());
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);
    let engine = Arc::new(
        Engine::builder()
            .listen(
                Listener::tcp(addr)
                    .threads(1)
                    .serve(flash_http::serve(t.http())),
            )
            .listen(Listener::udp(addr).threads(1).serve(t.udp()))
            .build()
            .unwrap(),
    );
    engine.start().unwrap();
    (t, engine, addr)
}

fn cfg(utp: bool, enc: Policy) -> ClientConfig {
    let mut c = ClientConfig::default();
    c.listen = "127.0.0.1:0".parse().unwrap();
    c.utp = utp;
    c.encryption = enc;
    c.dht = false;
    c.tracker_timeout = Duration::from_millis(500);
    c
}

fn seeder(mi: &MetaInfo, payload: &[u8], c: ClientConfig) -> Client {
    let client = Client::new(c).unwrap();
    let mut o = AddOptions::default();
    o.storage = Some(Arc::new(MemoryStorage::with_data(payload.to_vec())));
    let t = client.add_torrent(mi.clone(), o).unwrap();
    assert!(t.wait_complete(Duration::from_secs(10)), "seeder check");
    assert_eq!(t.stats().status, TorrentStatus::Seeding);
    client
}

fn leech(
    mi: &MetaInfo,
    c: ClientConfig,
    peers: Vec<SocketAddr>,
) -> (
    Client,
    Arc<MemoryStorage>,
    flash_bittorrent::client::Torrent,
) {
    let client = Client::new(c).unwrap();
    let store = Arc::new(MemoryStorage::new(mi.info.total_length));
    let mut o = AddOptions::default();
    o.storage = Some(store.clone());
    o.peers = peers;
    let t = client.add_torrent(mi.clone(), o).unwrap();
    (client, store, t)
}

#[test]
fn tcp_and_utp_with_and_without_mse_via_trackers() {
    let (_tr, _te, taddr) = tracker();
    let payload = data(3 << 20, 7);
    let mi = Builder::new("swarm.bin")
        .piece_length(64 * 1024)
        .tracker(format!("http://{taddr}/announce"))
        .tracker(format!("udp://{taddr}/announce"))
        .build_bytes(&payload)
        .unwrap();
    let mi = MetaInfo::parse(&mi.to_bytes()).unwrap();
    let seed = seeder(&mi, &payload, cfg(true, Policy::Prefer));
    let setups = [
        ("tcp plaintext", false, Policy::Disabled),
        ("tcp mse", false, Policy::Require),
        ("utp plaintext", true, Policy::Disabled),
        ("utp mse", true, Policy::Require),
    ];
    let mut leechers = Vec::new();
    for (name, utp, enc) in setups {
        leechers.push((name, leech(&mi, cfg(utp, enc), Vec::new())));
    }
    for (name, (_c, store, t)) in &leechers {
        assert!(
            t.wait_complete(Duration::from_secs(60)),
            "{name}: {:?}",
            t.stats()
        );
        assert!(store.snapshot() == payload, "{name}: data differs");
    }
    // The connections were what the setups asked for (as seen by the seeder too).
    for (name, (_c, _s, t)) in &leechers {
        let st = t.stats();
        assert_eq!(st.status, TorrentStatus::Seeding, "{name}");
        assert_eq!(st.hash_fails, 0, "{name}");
    }
    let sp = seed.torrents()[0].stats();
    assert!(sp.uploaded > 0, "{sp:?}");
    seed.close();
    for (_, (c, _, _)) in leechers {
        c.close();
    }
}

#[test]
fn transports_are_the_ones_asked_for() {
    let payload = data(1 << 20, 3);
    let mi = Builder::new("t.bin")
        .piece_length(32 * 1024)
        .build_bytes(&payload)
        .unwrap();
    // The seeder's last piece is corrupt: it has 31 of 32 pieces, so leechers stay connected.
    let mut broken = payload.clone();
    let last = broken.len() - 1;
    broken[last] ^= 0xFF;
    let seed = Client::new(cfg(true, Policy::Prefer)).unwrap();
    let mut o = AddOptions::default();
    o.storage = Some(Arc::new(MemoryStorage::with_data(broken)));
    let st = seed.add_torrent(mi.clone(), o).unwrap();
    for _ in 0..100 {
        if st.stats().status == TorrentStatus::Downloading {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(st.stats().pieces_have, 31);
    for (utp, enc) in [
        (true, Policy::Require),
        (false, Policy::Require),
        (true, Policy::Disabled),
        (false, Policy::Disabled),
    ] {
        let (c, store, t) = leech(&mi, cfg(utp, enc), vec![seed.listen_addr()]);
        let mut ok = false;
        for _ in 0..300 {
            if t.stats().pieces_have == 31 {
                ok = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(ok, "{:?}", t.stats());
        let peers = t.peers();
        assert_eq!(peers.len(), 1, "{peers:?}");
        assert_eq!(peers[0].utp, utp, "{peers:?}");
        assert_eq!(peers[0].encrypted, enc == Policy::Require, "{peers:?}");
        let got = store.snapshot();
        assert!(got[..31 * 32 * 1024] == payload[..31 * 32 * 1024]);
        c.close();
    }
    seed.close();
}

#[test]
fn magnet_metadata_exchange() {
    let payload = data(700_000, 11);
    let files = vec![
        (vec!["a.txt".to_owned()], payload[..300_000].to_vec()),
        (
            vec!["dir".to_owned(), "b.bin".to_owned()],
            payload[300_000..].to_vec(),
        ),
    ];
    let mi = Builder::new("multi")
        .piece_length(16 * 1024)
        .build_files(&files)
        .unwrap();
    let seed = seeder(&mi, &payload, cfg(false, Policy::Prefer));
    let magnet = format!("{}&x.pe={}", mi.magnet(), seed.listen_addr());
    let client = Client::new(cfg(true, Policy::Prefer)).unwrap();
    let store = Arc::new(MemoryStorage::new(mi.info.total_length));
    let mut o = AddOptions::default();
    o.storage = Some(store.clone());
    let t = client.add_magnet(&magnet, o).unwrap();
    assert!(t.wait_metadata(Duration::from_secs(20)), "{:?}", t.stats());
    assert_eq!(t.info().unwrap().info_hash(), mi.info_hash);
    assert!(t.wait_complete(Duration::from_secs(30)), "{:?}", t.stats());
    assert!(store.snapshot() == payload);
    // The fetched info dictionary round-trips into a .torrent.
    assert_eq!(t.metainfo().unwrap().info_hash, mi.info_hash);
    client.close();
    seed.close();
}

#[test]
fn files_on_disk_resume_and_seed() {
    let dir = std::env::temp_dir().join(format!("flash-bt-swarm-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let src = dir.join("src");
    std::fs::create_dir_all(src.join("pack/sub")).unwrap();
    let a = data(200_000, 5);
    let b = data(123_457, 6);
    std::fs::write(src.join("pack/a.bin"), &a).unwrap();
    std::fs::write(src.join("pack/sub/b.bin"), &b).unwrap();
    let mi = Builder::new("pack")
        .piece_length(32 * 1024)
        .build_path(src.join("pack"))
        .unwrap();
    // The seeder finds its files by checking them.
    let mut sc = cfg(false, Policy::Prefer);
    sc.data_dir = src;
    let seed = Client::new(sc).unwrap();
    let st = seed.add_torrent(mi.clone(), AddOptions::default()).unwrap();
    assert!(
        st.wait_complete(Duration::from_secs(10)),
        "{:?}",
        st.stats()
    );
    // A leecher writes files below its own directory.
    let mut lc = cfg(true, Policy::Prefer);
    lc.data_dir = dir.join("dst");
    let leecher = Client::new(lc.clone()).unwrap();
    let mut o = AddOptions::default();
    o.peers = vec![seed.listen_addr()];
    let t = leecher.add_torrent(mi.clone(), o).unwrap();
    assert!(t.wait_complete(Duration::from_secs(30)), "{:?}", t.stats());
    leecher.close();
    assert_eq!(std::fs::read(dir.join("dst/pack/a.bin")).unwrap(), a);
    assert_eq!(std::fs::read(dir.join("dst/pack/sub/b.bin")).unwrap(), b);
    // Restarted on the same directory, it is complete after the check, with no peer.
    let again = Client::new(lc).unwrap();
    let t = again.add_torrent(mi, AddOptions::default()).unwrap();
    assert!(t.wait_complete(Duration::from_secs(10)), "{:?}", t.stats());
    assert_eq!(t.stats().downloaded, 0);
    again.close();
    seed.close();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn dht_finds_the_seeder() {
    // A small DHT: one bootstrap client and two more; the seeder announces, the leecher looks.
    let mut c0 = cfg(true, Policy::Prefer);
    c0.dht = true;
    let router = Client::new(c0.clone()).unwrap();
    let boot = vec![router.listen_addr()];
    let mut cs = c0;
    cs.dht_bootstrap = boot;
    let extra: Vec<Client> = (0..3).map(|_| Client::new(cs.clone()).unwrap()).collect();
    std::thread::sleep(Duration::from_millis(500));
    let payload = data(500_000, 21);
    let mi = Builder::new("dht.bin")
        .piece_length(16 * 1024)
        .build_bytes(&payload)
        .unwrap();
    let seed = seeder(&mi, &payload, cs.clone());
    // Let the seeder's announce reach the DHT.
    std::thread::sleep(Duration::from_secs(2));
    assert!(
        seed.dht_nodes() >= 2,
        "seeder knows {} nodes",
        seed.dht_nodes()
    );
    let (leecher, store, t) = leech(&mi, cs, Vec::new());
    assert!(t.wait_complete(Duration::from_secs(60)), "{:?}", t.stats());
    assert!(store.snapshot() == payload);
    leecher.close();
    seed.close();
    for c in extra {
        c.close();
    }
    router.close();
}

#[test]
fn pex_spreads_peers() {
    // Nobody has data; B and C only know H. H tells each about the other, and they connect.
    let payload = data(400_000, 31);
    let mi = Builder::new("pex.bin")
        .piece_length(16 * 1024)
        .build_bytes(&payload)
        .unwrap();
    let (h, _hs, _ht) = leech(&mi, cfg(false, Policy::Prefer), Vec::new());
    let (b, _bs, bt) = leech(&mi, cfg(false, Policy::Prefer), vec![h.listen_addr()]);
    let (c, _cs, _ct) = leech(&mi, cfg(false, Policy::Prefer), vec![h.listen_addr()]);
    let mut ok = false;
    for _ in 0..100 {
        if bt
            .peers()
            .iter()
            .any(|p| p.addr == c.listen_addr() || p.id == c.peer_id())
        {
            ok = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(ok, "B's peers: {:?}", bt.peers());
    c.close();
    b.close();
    h.close();
}
