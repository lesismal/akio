//! Throughput between two `Endpoint`s over loopback, for same-run A/B comparisons
//! (`quiet.sh` on the benchmark host):
//!
//! ```text
//! webrtc-bench media [secs]   one-way VP8 RTP (8 kB frames written as fast as they go out):
//!                             media bytes the receiver got per second
//! webrtc-bench dc [secs]      one data channel, 64 kB messages kept queued: bytes per second
//! webrtc-bench audio [secs]   one-way Opus RTP (160-byte frames, timestamps following the wall
//!                             clock, up to one frame per 48 kHz tick): thousand frames per
//!                             second, and the process's CPU microseconds per frame (Linux)
//! webrtc-bench audio-jb [secs]  the same into the receiver's audio jitter buffer (ADR-087)
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
    /// Count frames, not bytes.
    frames: bool,
}

impl PeerHandler for Sink {
    fn on_connected(&mut self, _p: &Peer) {
        let _ = self.up.lock().unwrap().send(());
    }
    fn on_channel_open(&mut self, _p: &Peer, _id: ChannelId, _label: &str) {
        let _ = self.up.lock().unwrap().send(());
    }
    fn on_media_data(&mut self, _p: &Peer, d: &MediaData) {
        let n = if self.frames { 1 } else { d.data.len() as u64 };
        self.bytes.fetch_add(n, Ordering::Relaxed);
    }
    fn on_channel_data(&mut self, _p: &Peer, _id: ChannelId, d: &[u8], _b: bool) {
        self.bytes.fetch_add(d.len() as u64, Ordering::Relaxed);
    }
}

/// CPU time of this process's threads (Linux `/proc/self/task/*/schedstat`, nanoseconds).
fn cpu_time() -> Option<Duration> {
    let mut ns = 0u64;
    for t in std::fs::read_dir("/proc/self/task").ok()? {
        let stat = std::fs::read_to_string(t.ok()?.path().join("schedstat")).ok()?;
        ns += stat.split(' ').next()?.parse::<u64>().ok()?;
    }
    Some(Duration::from_nanos(ns))
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let mode = a.get(1).map_or("media", String::as_str).to_owned();
    let secs: u64 = a.get(2).and_then(|s| s.parse().ok()).unwrap_or(5);
    let e = Arc::new(Engine::builder().udp_client_threads(1).build().unwrap());
    e.start().unwrap();
    let jb = mode == "audio-jb";
    let cfg = || rtc_config().set_sctp_max_buffered_amount(8 << 20);
    let ea = Endpoint::bind(&e, "127.0.0.1:0".parse().unwrap())
        .unwrap()
        .config(cfg);
    let eb = Endpoint::bind(&e, "127.0.0.1:0".parse().unwrap())
        .unwrap()
        .config(move || {
            let c = cfg();
            if jb {
                c.set_audio_jitter_buffer(Some(only_rtp::PlayoutDelay::default())) // JB-ONLY
            } else {
                c
            }
        });
    let (txa, rxa) = channel();
    let (txb, rxb) = channel();
    let got = Arc::new(AtomicU64::new(0));
    let (mut video, mut ch, mut voice) = (None, None, None);
    let audio = mode.starts_with("audio");
    let media = mode == "media" || audio;
    let (pa, offer) = ea
        .create_offer(
            Sink {
                bytes: Arc::new(AtomicU64::new(0)),
                up: Mutex::new(txa),
                frames: audio,
            },
            |api| {
                if audio {
                    voice = Some(api.add_media(MediaKind::Audio, Direction::SendOnly, None, None));
                } else if media {
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
                frames: audio,
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
    let mut cpu: Option<Duration> = None;
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
    } else if let Some(v) = voice {
        let pt = pa.payload_type(v, Codec::Opus).unwrap();
        let mut f = vec![0xfcu8; 160];
        let mut i = 0u64;
        let mut last = 0;
        let mut cpu0 = None;
        while start.elapsed() < warm + Duration::from_secs(secs) {
            if base.is_none() && start.elapsed() >= warm {
                base = Some((Instant::now(), got.load(Ordering::Relaxed)));
                cpu0 = cpu_time();
            }
            f[1] = i as u8;
            // 48 kHz ticks of the wall clock, strictly increasing: at most a frame per tick,
            // so media time keeps up with real time (a jitter buffer plays it in real time).
            let real = start.elapsed().as_micros() as u64 * 48 / 1000;
            if last + 1 > real + 16 {
                std::thread::sleep(Duration::from_micros((last + 1 - real) * 1000 / 48));
            }
            let ticks = (start.elapsed().as_micros() as u64 * 48 / 1000).max(last + 1);
            last = ticks;
            let t = MediaTime::new(ticks, Frequency::FORTY_EIGHT_KHZ);
            pa.write_media(v, pt, Instant::now(), t, &f).unwrap();
            i += 1;
            if i % 16 == 0 {
                std::thread::sleep(Duration::from_micros(200));
            }
        }
        cpu = cpu0.zip(cpu_time()).and_then(|(a, b)| b.checked_sub(a));
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
    let per_s = (got.load(Ordering::Relaxed) - b0) as f64 / t0.elapsed().as_secs_f64();
    if audio {
        // Process CPU time (both peers) per frame received, where /proc tells it.
        let frames = got.load(Ordering::Relaxed) - b0;
        let us = cpu.map_or(0.0, |c| c.as_secs_f64() * 1e6 / frames.max(1) as f64);
        println!("BENCH {mode} {:.1} {us:.2}", per_s / 1e3);
    } else {
        println!("BENCH {mode} {:.1}", per_s / 1e6);
    }
    pa.close();
    ea.close();
    eb.close();
    e.shutdown();
}
