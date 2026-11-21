//! Throughput between two `Endpoint`s over loopback, for same-run A/B comparisons
//! (`quiet.sh` on the benchmark host):
//!
//! ```text
//! webrtc-bench media [secs]   one-way VP8 RTP (8 kB frames written as fast as they go out):
//!                             media bytes the receiver got per second
//! webrtc-bench dc [secs]      one data channel, 64 kB messages kept queued: bytes per second
//! ```
//!
//! Prints one `BENCH <mode> <MB/s>` line. Default configurations on both sides (no estimator,
//! no pacing), so the result measures the send and receive paths themselves.
#![allow(missing_docs)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use only::Engine;
use only_webrtc::{
    ChannelId, Codec, Direction, Endpoint, Frequency, MediaData, MediaKind, MediaTime, Peer,
    PeerHandler, rtc_config,
};

struct Sink {
    bytes: Arc<AtomicU64>,
    up: Mutex<Sender<()>>,
}

impl PeerHandler for Sink {
    fn on_connected(&mut self, _p: &Peer) {
        let _ = self.up.lock().unwrap().send(());
    }
    fn on_channel_open(&mut self, _p: &Peer, _id: ChannelId, _label: &str) {
        let _ = self.up.lock().unwrap().send(());
    }
    fn on_media_data(&mut self, _p: &Peer, d: &MediaData) {
        self.bytes.fetch_add(d.data.len() as u64, Ordering::Relaxed);
    }
    fn on_channel_data(&mut self, _p: &Peer, _id: ChannelId, d: &[u8], _b: bool) {
        self.bytes.fetch_add(d.len() as u64, Ordering::Relaxed);
    }
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let mode = a.get(1).map_or("media", String::as_str).to_owned();
    let secs: u64 = a.get(2).and_then(|s| s.parse().ok()).unwrap_or(5);
    let e = Arc::new(Engine::builder().udp_client_threads(1).build().unwrap());
    e.start().unwrap();
    let cfg = || rtc_config().set_sctp_max_buffered_amount(8 << 20);
    let ea = Endpoint::bind(&e, "127.0.0.1:0".parse().unwrap())
        .unwrap()
        .config(cfg);
    let eb = Endpoint::bind(&e, "127.0.0.1:0".parse().unwrap())
        .unwrap()
        .config(cfg);
    let (txa, rxa) = channel();
    let (txb, rxb) = channel();
    let got = Arc::new(AtomicU64::new(0));
    let (mut video, mut ch) = (None, None);
    let media = mode == "media";
    let (pa, offer) = ea
        .create_offer(
            Sink {
                bytes: Arc::new(AtomicU64::new(0)),
                up: Mutex::new(txa),
            },
            |api| {
                if media {
                    video = Some(api.add_media(MediaKind::Video, Direction::SendOnly, None, None));
                } else {
                    ch = Some(api.add_channel("bench"));
                }
            },
        )
        .unwrap();
    let (_pb, answer) = eb
        .accept_offer(
            &offer,
            Sink {
                bytes: got.clone(),
                up: Mutex::new(txb),
            },
        )
        .unwrap();
    pa.accept_answer(&answer).unwrap();
    rxa.recv_timeout(Duration::from_secs(10))
        .expect("connected");
    if !media {
        rxb.recv_timeout(Duration::from_secs(10)).expect("open");
    }
    let warm = Duration::from_secs(1);
    let start = Instant::now();
    let mut base = None;
    if let Some(v) = video {
        let pt = pa.payload_type(v, Codec::Vp8).unwrap();
        let mut f = vec![0x11u8; 8000];
        f[0] = 0x10;
        let mut i = 0u64;
        while start.elapsed() < warm + Duration::from_secs(secs) {
            if base.is_none() && start.elapsed() >= warm {
                base = Some((Instant::now(), got.load(Ordering::Relaxed)));
            }
            f[1] = i as u8;
            let t = MediaTime::new(i * 3000, Frequency::NINETY_KHZ);
            pa.write_media(v, pt, Instant::now(), t, &f).unwrap();
            f[0] = 0x11;
            i += 1;
            if i % 16 == 0 {
                // Let the receiver keep up (loopback drops what overflows its buffer).
                std::thread::sleep(Duration::from_micros(200));
            }
        }
    } else if let Some(c) = ch {
        let msg = vec![7u8; 64 * 1024];
        while start.elapsed() < warm + Duration::from_secs(secs) {
            if base.is_none() && start.elapsed() >= warm {
                base = Some((Instant::now(), got.load(Ordering::Relaxed)));
            }
            if !pa.send(c, &msg, true).unwrap() {
                std::thread::sleep(Duration::from_micros(100));
            }
        }
    }
    let (t0, b0) = base.expect("warmed up");
    let mb = (got.load(Ordering::Relaxed) - b0) as f64 / t0.elapsed().as_secs_f64() / 1e6;
    println!("BENCH {mode} {mb:.1}");
    pa.close();
    ea.close();
    eb.close();
    e.shutdown();
}
