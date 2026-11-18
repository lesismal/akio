//! Hot-path benchmarks of the hub and the ingests (ignored by default; run in release):
//!
//! ```text
//! cargo test -p only-media --release --test media_bench -- --ignored --nocapture
//! ```
//!
//! Each prints `BENCH <name> <ns>`: the best of seven runs, in nanoseconds per packet (fan-out:
//! per packet written, all subscribers included; FLV: per tag decoded). Used for same-run A/B
//! comparisons between commits (only the public API, so the file runs on older trees too).

use std::{
    hint::black_box,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use only_media::{
    Hub, Packet, PeerInfo, Tracks, flv,
    hub::{HubConfig, Sink, SubscribeOptions},
};

const FLVS: [(&str, &[u8]); 2] = [
    ("h264", include_bytes!("../testdata/h264_aac.flv")),
    ("h265", include_bytes!("../testdata/h265_aac.flv")),
];

fn flv_sample(data: &[u8]) -> (Tracks, Vec<Packet>) {
    let mut dec = flv::Decoder::new();
    let (mut tracks, mut pkts) = (None, Vec::new());
    for t in flv::Demuxer::new().feed(data).unwrap() {
        for e in dec.write(t.tag_type, t.ts, &t.body) {
            match e {
                flv::Event::Tracks(t) => tracks = Some(t),
                flv::Event::Packet(p) => pkts.push(p),
                _ => {}
            }
        }
    }
    (tracks.unwrap(), pkts)
}

/// The best of seven runs of `f`, which handles `n` items and returns the time it measured,
/// in ns per item.
fn best(n: usize, mut f: impl FnMut() -> Duration) -> f64 {
    (0..7)
        .map(|_| f().as_nanos() as f64 / n as f64)
        .fold(f64::MAX, f64::min)
}

struct Count(Arc<AtomicU64>);

impl Sink for Count {
    fn on_tracks(&mut self, _tracks: &Tracks) {}
    fn on_packet(&mut self, pkt: &Arc<Packet>) {
        self.0.fetch_add(pkt.data.len() as u64, Ordering::Relaxed);
    }
}

/// One publisher, 1 / 16 / 256 subscribers: the cost of `Publisher::write` (GOP cache and
/// delivery to every subscriber).
#[test]
#[ignore]
fn bench_fanout() {
    let (tracks, pkts) = flv_sample(FLVS[0].1);
    let span = pkts.iter().map(|p| p.dts).max().unwrap() + 40_000_000;
    let rounds = 40;
    for subs in [1usize, 16, 256] {
        let mut cfg = HubConfig::default();
        cfg.max_subscribers = cfg.max_subscribers.max(subs + 1);
        let hub = Hub::new(cfg);
        let publisher = hub
            .publish("b/fan", tracks.clone(), PeerInfo::default())
            .unwrap();
        let seen = Arc::new(AtomicU64::new(0));
        let _subs: Vec<_> = (0..subs)
            .map(|_| {
                let opts = SubscribeOptions::new(PeerInfo::default());
                hub.subscribe("b/fan", Count(seen.clone()), opts).unwrap()
            })
            .collect();
        let mut round = 0i64;
        let n = rounds * pkts.len();
        let ns = best(n, || {
            let all: Vec<Arc<Packet>> = (0..rounds as i64)
                .flat_map(|r| {
                    pkts.iter().map(move |p| {
                        let mut q = p.clone();
                        q.dts += (round + r) * span;
                        q.pts += (round + r) * span;
                        Arc::new(q)
                    })
                })
                .collect();
            round += rounds as i64;
            let t = Instant::now();
            for p in all {
                publisher.write_shared(p);
            }
            t.elapsed()
        });
        assert!(seen.load(Ordering::Relaxed) > 0);
        println!("BENCH fanout-{subs} {ns:.1}");
    }
}

/// FLV tag decoding (the RTMP and HTTP-FLV ingest path): H.264 + AAC and H.265 + AAC.
#[test]
#[ignore]
fn bench_flv_decode() {
    for (name, data) in FLVS {
        let tags = flv::Demuxer::new().feed(data).unwrap();
        let rounds = 50;
        let ns = best(rounds * tags.len(), || {
            let t0 = Instant::now();
            let mut dec = flv::Decoder::new();
            let mut n = 0usize;
            for r in 0..rounds as u32 {
                for t in &tags {
                    n += dec.write(t.tag_type, t.ts + r * 2100, &t.body).len();
                }
            }
            black_box(n);
            t0.elapsed()
        });
        println!("BENCH flv-{name} {ns:.1}");
    }
}
