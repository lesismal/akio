//! Loopback swarm throughput: one seeder and one leecher in this process, the torrent in memory
//! (`MemoryStorage`), so the peer wire path (requests, pieces, choking, hashing on the pool) is
//! what is measured, not the disk.
//!
//! ```text
//! bt-bench [MiB=256] [rounds=5] [tcp|utp] [plain|rc4]
//! ```
//! Prints MiB/s per round and the median.

use std::sync::Arc;
use std::time::{Duration, Instant};

use only_bittorrent::client::{AddOptions, Client, ClientConfig, MemoryStorage};
use only_bittorrent::metainfo::Builder;
use only_bittorrent::mse::Policy;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mib: usize = args.get(1).and_then(|a| a.parse().ok()).unwrap_or(256);
    let rounds: usize = args.get(2).and_then(|a| a.parse().ok()).unwrap_or(5);
    let utp = args.get(3).is_some_and(|a| a == "utp");
    let rc4 = args.get(4).is_some_and(|a| a == "rc4");
    let mut x = 0x9e37_79b9u32;
    let payload: Vec<u8> = (0..mib << 20)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect();
    let mi = Builder::new("bench.bin")
        .piece_length(256 * 1024)
        .build_bytes(&payload)
        .expect("torrent");
    let cfg = || {
        let mut c = ClientConfig::default();
        c.listen = "127.0.0.1:0".parse().expect("addr");
        c.dht = false;
        c.utp = utp;
        c.encryption = if rc4 {
            Policy::Require
        } else {
            Policy::Disabled
        };
        c.threads = 2;
        c
    };
    let seed = Client::new(cfg()).expect("seeder");
    let mut o = AddOptions::default();
    o.storage = Some(Arc::new(MemoryStorage::with_data(payload.clone())));
    o.seed = true;
    seed.add_torrent(mi.clone(), o).expect("seed torrent");
    let mut speeds = Vec::new();
    for r in 0..rounds {
        let c = Client::new(cfg()).expect("leecher");
        let store = Arc::new(MemoryStorage::new(mi.info.total_length));
        let mut o = AddOptions::default();
        o.storage = Some(store.clone());
        o.peers = vec![seed.listen_addr()];
        let start = Instant::now();
        let t = c.add_torrent(mi.clone(), o).expect("leech torrent");
        assert!(t.wait_complete(Duration::from_secs(600)), "{:?}", t.stats());
        let secs = start.elapsed().as_secs_f64();
        assert!(store.snapshot() == payload);
        let s = mib as f64 / secs;
        println!("round {r}: {s:.1} MiB/s ({secs:.2} s)");
        speeds.push(s);
        c.close();
    }
    speeds.sort_by(f64::total_cmp);
    println!("median {:.1} MiB/s", speeds[speeds.len() / 2]);
    seed.close();
}
