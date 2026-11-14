//! Companion of the book's "BitTorrent" chapter: a tracker, a seeder and a leecher (by magnet
//! link) in one process, on loopback.
//!
//! `cargo run -p only-bittorrent --example guide-bittorrent`

use std::sync::Arc;
use std::time::Duration;

use only::{Engine, Listener};
use only_bittorrent::client::{AddOptions, Client, ClientConfig, MemoryStorage, TorrentEvent};
use only_bittorrent::metainfo::Builder;
use only_bittorrent::mse::Policy;
use only_bittorrent::tracker::{TrackerConfig, TrackerServer};

fn main() -> std::io::Result<()> {
    // ANCHOR: tracker
    let tracker = TrackerServer::new(TrackerConfig::default());
    let taddr = "127.0.0.1:6969".parse().expect("address");
    let tengine = Engine::builder()
        .listen(
            Listener::tcp(taddr)
                .threads(1)
                .serve(only_http::serve(tracker.http())),
        )
        .listen(Listener::udp(taddr).threads(1).serve(tracker.udp()))
        .build()?;
    tengine.start()?;
    // ANCHOR_END: tracker

    // ANCHOR: torrent
    let data: Vec<u8> = (0..4 << 20).map(|i: u32| (i % 251) as u8).collect();
    let mi = Builder::new("guide.bin")
        .piece_length(256 * 1024)
        .tracker("http://127.0.0.1:6969/announce")
        .tracker("udp://127.0.0.1:6969/announce")
        .build_bytes(&data)
        .expect("torrent");
    std::fs::write(std::env::temp_dir().join("guide.torrent"), mi.to_bytes())?;
    // ANCHOR_END: torrent

    // ANCHOR: seeder
    let mut cfg = ClientConfig::default();
    cfg.listen = "127.0.0.1:0".parse().expect("address"); // a port free for TCP and UDP
    cfg.dht = false;
    let seeder = Client::new(cfg)?;
    let mut opts = AddOptions::default();
    opts.storage = Some(Arc::new(MemoryStorage::with_data(data.clone())));
    opts.seed = true; // made from this data: no hash check
    seeder.add_torrent(mi.clone(), opts).expect("add");
    // ANCHOR_END: seeder

    // ANCHOR: leecher
    let mut cfg = ClientConfig::default();
    cfg.listen = "127.0.0.1:0".parse().expect("address");
    cfg.dht = false;
    cfg.encryption = Policy::Require; // MSE/RC4 only
    cfg.on_event = Some(Arc::new(|ih, e| {
        if !matches!(e, TorrentEvent::PieceVerified(_)) {
            println!("[{}] {e:?}", &ih.to_hex()[..8]);
        }
    }));
    let leecher = Client::new(cfg)?;
    let store = Arc::new(MemoryStorage::new(mi.info.total_length));
    let mut opts = AddOptions::default();
    opts.storage = Some(store.clone());
    let t = leecher
        .add_magnet(&mi.magnet().to_string(), opts)
        .expect("magnet");
    assert!(t.wait_metadata(Duration::from_secs(10)), "metadata");
    assert!(t.wait_complete(Duration::from_secs(30)), "download");
    println!("{:?}", t.stats());
    assert!(store.snapshot() == data);
    // ANCHOR_END: leecher

    leecher.close();
    seeder.close();
    tengine.shutdown();
    Ok(())
}
