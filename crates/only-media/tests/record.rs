//! Recording hub streams to files (`only_media::record`): fMP4 and FLV, cut by duration and by
//! size, rotation, hooks, a republish with other codecs, a writer that does not keep up, and
//! file names. With ffprobe every file must parse and decode, start with a keyframe and hold
//! the media its hook reported; without it the ffmpeg checks are skipped.

use std::{
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{Sender, channel},
    },
    time::{Duration, SystemTime},
};

use only_media::{
    Hub, HubError, Packet, PeerInfo, Tracks,
    av::{MILLISECOND, SECOND, Time},
    flv,
    record::{RecordConfig, RecordFile, RecordFormat, RecordHooks, Recorder},
};

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

fn h264() -> (Tracks, Vec<Packet>) {
    flv_sample(include_bytes!("../testdata/h264_aac.flv"))
}

fn h265() -> (Tracks, Vec<Packet>) {
    flv_sample(include_bytes!("../testdata/h265_aac.flv"))
}

/// Publishes `rounds` copies of the sample back to back (not in real time) on `path`.
fn publish(hub: &Hub, path: &str, (tracks, pkts): &(Tracks, Vec<Packet>), rounds: i64) -> Time {
    let first = pkts.iter().map(|p| p.dts).min().unwrap();
    let last = pkts.iter().map(|p| p.dts).max().unwrap();
    let span = last - first + 40 * MILLISECOND;
    let p = hub
        .publish(path, tracks.clone(), PeerInfo::default())
        .unwrap();
    for round in 0..rounds {
        for pkt in pkts {
            let mut q = pkt.clone();
            q.dts += round * span;
            q.pts += round * span;
            p.write(q);
        }
    }
    p.close();
    span * rounds
}

#[derive(Debug, Clone)]
enum Ev {
    Start(RecordFile),
    Stop(RecordFile, Option<String>),
    Remove(PathBuf),
}

/// Hooks reporting every event on a channel; `gate` holds `on_start` while set.
struct Hooks {
    tx: Mutex<Sender<Ev>>,
    gate: Arc<AtomicBool>,
}

impl RecordHooks for Hooks {
    fn on_start(&self, file: &RecordFile) {
        while self.gate.load(Ordering::Acquire) {
            std::thread::sleep(Duration::from_millis(5));
        }
        let _ = self.tx.lock().unwrap().send(Ev::Start(file.clone()));
    }

    fn on_stop(&self, file: &RecordFile, result: Result<(), &std::io::Error>) {
        let err = result.err().map(ToString::to_string);
        let _ = self.tx.lock().unwrap().send(Ev::Stop(file.clone(), err));
    }

    fn on_remove(&self, path: &Path) {
        let _ = self.tx.lock().unwrap().send(Ev::Remove(path.to_owned()));
    }
}

fn dir(name: &str) -> PathBuf {
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("record-{name}"));
    let _ = std::fs::remove_dir_all(&d);
    d
}

fn stops(evs: &[Ev]) -> Vec<RecordFile> {
    evs.iter()
        .filter_map(|e| match e {
            Ev::Stop(f, err) => {
                assert!(err.is_none(), "{f:?}: {err:?}");
                Some(f.clone())
            }
            _ => None,
        })
        .collect()
}

fn ffprobe() -> bool {
    let ok = Command::new("ffprobe")
        .arg("-version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if !ok {
        eprintln!("ffprobe not found: ffmpeg checks skipped");
    }
    ok
}

fn run(cmd: &str, args: &[&str]) -> String {
    let out = Command::new(cmd).args(args).output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{cmd} {args:?}: {err}");
    assert!(err.trim().is_empty(), "{cmd} {args:?}: {err}");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// ffprobe and ffmpeg accept `f`: it decodes without a message, its codecs are `codecs`, its
/// first video packet is a keyframe at 0, and its video lasts about `f.duration`.
fn check_file(f: &RecordFile, codecs: &[&str]) {
    let p = f.path.to_str().unwrap();
    assert_eq!(std::fs::metadata(p).unwrap().len(), f.bytes, "{p}");
    run(
        "ffmpeg",
        &["-nostdin", "-v", "error", "-i", p, "-f", "null", "-"],
    );
    let streams = run(
        "ffprobe",
        &[
            "-v",
            "error",
            "-show_entries",
            "stream=codec_name",
            "-of",
            "csv=p=0",
            p,
        ],
    );
    let got: Vec<&str> = streams
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    assert_eq!(got, codecs, "{p}");
    let pkts = run(
        "ffprobe",
        &[
            "-v",
            "error",
            "-select_streams",
            "v:0",
            "-show_entries",
            "packet=pts_time,dts_time,flags",
            "-of",
            "csv=p=0",
            p,
        ],
    );
    let lines: Vec<&str> = pkts.lines().filter(|l| !l.is_empty()).collect();
    assert!(lines.len() > 5, "{p}: {pkts}");
    assert!(lines[0].contains('K'), "{p}: {}", lines[0]);
    let dts: Vec<f64> = lines
        .iter()
        .map(|l| l.split(',').nth(1).unwrap().parse().unwrap())
        .collect();
    assert!(dts[0].abs() < 0.1, "{p}: first dts {}", dts[0]);
    let last = dts.iter().copied().fold(0.0, f64::max);
    let want = f.duration.as_secs_f64();
    assert!(
        (last - want).abs() < 0.2,
        "{p}: video to {last}, reported {want}"
    );
}

fn check_format(format: RecordFormat) {
    let ff = ffprobe();
    let sample = h264();
    let hub = Hub::default();
    let (tx, rx) = channel();
    let hooks = Hooks {
        tx: Mutex::new(tx),
        gate: Arc::default(),
    };
    let mut cfg = RecordConfig::new(dir(&format!("dur-{}", format.extension())));
    cfg.format = format;
    cfg.segment_duration = Some(Duration::from_secs(3));
    cfg.wait = None;
    let rec = Recorder::with_hooks(hub.clone(), cfg, hooks);
    let p = hub
        .publish("live/cam", sample.0.clone(), PeerInfo::default())
        .unwrap();
    rec.start("live/cam").unwrap();
    let first = sample.1.iter().map(|p| p.dts).min().unwrap();
    let last = sample.1.iter().map(|p| p.dts).max().unwrap();
    let span = last - first + 40 * MILLISECOND;
    for round in 0..6 {
        for pkt in &sample.1 {
            let mut q = pkt.clone();
            q.dts += round * span;
            q.pts += round * span;
            p.write(q);
        }
    }
    p.close(); // without `wait`, the recording ends with the publisher
    drop(rec);
    // The writer ends once the recorder and its recording are gone: every event is in.
    let evs: Vec<Ev> = rx.iter().collect();
    let starts: Vec<RecordFile> = evs
        .iter()
        .filter_map(|e| match e {
            Ev::Start(f) => Some(f.clone()),
            _ => None,
        })
        .collect();
    let files = stops(&evs);
    assert_eq!(starts.len(), files.len());
    for (i, (a, b)) in starts.iter().zip(&files).enumerate() {
        assert_eq!(
            (a.index, a.bytes, a.duration),
            (i as u64, 0, Duration::ZERO)
        );
        assert_eq!(a.path, b.path);
    }
    let media: f64 = files.iter().map(|f| f.duration.as_secs_f64()).sum();
    let want = (6 * span) as f64 / SECOND as f64;
    assert!(files.len() >= 3, "{files:#?}");
    assert!((media - want).abs() < 1.0, "{media} of {want}");
    for f in &files {
        assert!(f.path.starts_with(rec_dir(&files)), "{f:?}");
        let name = f.path.file_name().unwrap().to_str().unwrap();
        assert!(name.starts_with("live_cam-"), "{name}");
        assert!(
            name.ends_with(&format!("-{}.{}", f.index, format.extension())),
            "{name}"
        );
        // Cut at the first keyframe after 3 s.
        if f.index + 1 < files.len() as u64 {
            assert!(f.duration >= Duration::from_secs(3), "{f:?}");
        }
        if ff {
            check_file(f, &["h264", "aac"]);
        }
    }
}

fn rec_dir(files: &[RecordFile]) -> PathBuf {
    files[0].path.parent().unwrap().to_owned()
}

#[test]
fn fmp4_by_duration() {
    check_format(RecordFormat::Fmp4);
}

#[test]
fn flv_by_duration() {
    check_format(RecordFormat::Flv);
}

/// Cut by size, rotated to the newest two files; a republish with H.265 starts a new file.
#[test]
fn size_rotation_and_republish() {
    let ff = ffprobe();
    for format in [RecordFormat::Fmp4, RecordFormat::Flv] {
        let hub = Hub::default();
        let (tx, rx) = channel();
        let hooks = Hooks {
            tx: Mutex::new(tx),
            gate: Arc::default(),
        };
        let mut cfg = RecordConfig::new(dir(&format!("size-{}", format.extension())));
        cfg.format = format;
        cfg.segment_bytes = Some(30_000);
        cfg.max_files = 2;
        let rec = Recorder::with_hooks(hub.clone(), cfg, hooks);
        rec.start("live/r").unwrap();
        publish(&hub, "live/r", &h264(), 4);
        publish(&hub, "live/r", &h265(), 2);
        std::thread::sleep(Duration::from_millis(300));
        assert!(rec.stop("live/r"));
        drop(rec);
        // The writer ends once the recording is gone: every event is in.
        let evs: Vec<Ev> = rx.iter().collect();
        let files = stops(&evs);
        let removed: Vec<PathBuf> = evs
            .iter()
            .filter_map(|e| match e {
                Ev::Remove(p) => Some(p.clone()),
                _ => None,
            })
            .collect();
        assert!(files.len() >= 4, "{files:#?}");
        assert_eq!(removed.len(), files.len() - 2, "{evs:#?}");
        for (f, r) in files.iter().zip(&removed) {
            assert_eq!(&f.path, r);
            assert!(!f.path.exists());
        }
        let kept = &files[files.len() - 2..];
        let mut on_disk: Vec<PathBuf> = std::fs::read_dir(rec_dir(&files))
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        on_disk.sort();
        let mut want: Vec<PathBuf> = kept.iter().map(|f| f.path.clone()).collect();
        want.sort();
        assert_eq!(on_disk, want);
        // Size: cut at the first keyframe past 30 kB (a GOP of these samples is about
        // 20 kB, so no file is far above it).
        for f in &files[..files.len() - 1] {
            assert!(f.bytes >= 30_000 && f.bytes < 60_000, "{f:?}");
        }
        // The republish with H.265 started a new file: the last ones are H.265.
        if ff {
            check_file(&kept[1], &["hevc", "aac"]);
        }
    }
}

/// A writer that does not keep up: the queue stays bounded, packets are dropped while it is
/// full, and every file is still whole (it decodes, starts with a keyframe).
#[test]
fn slow_writer_drops_and_files_stay_valid() {
    let ff = ffprobe();
    let hub = Hub::default();
    let (tx, rx) = channel();
    let gate = Arc::new(AtomicBool::new(true));
    let hooks = Hooks {
        tx: Mutex::new(tx),
        gate: gate.clone(),
    };
    let mut cfg = RecordConfig::new(dir("slow"));
    cfg.max_queued_bytes = 20_000;
    cfg.wait = None;
    let rec = Recorder::with_hooks(hub.clone(), cfg, hooks);
    let sample = h264();
    let p = hub
        .publish("live/s", sample.0.clone(), PeerInfo::default())
        .unwrap();
    rec.start("live/s").unwrap();
    let first = sample.1.iter().map(|p| p.dts).min().unwrap();
    let last = sample.1.iter().map(|p| p.dts).max().unwrap();
    let span = last - first + 40 * MILLISECOND;
    let mut max_queued = 0;
    for round in 0..8 {
        if round == 4 {
            // The writer catches up.
            gate.store(false, Ordering::Release);
            while rec.queued_bytes() > 0 {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        for pkt in &sample.1 {
            let mut q = pkt.clone();
            q.dts += round * span;
            q.pts += round * span;
            p.write(q);
            max_queued = max_queued.max(rec.queued_bytes());
        }
    }
    p.close();
    assert!(rec.dropped() > 0);
    // One GOP over the bound at most.
    assert!(max_queued <= 20_000 + 40_000, "{max_queued}");
    drop(rec);
    let evs: Vec<Ev> = rx.iter().collect();
    let files = stops(&evs);
    assert!(files.len() >= 2, "{files:#?}");
    for f in &files {
        if ff {
            check_file(f, &["h264", "aac"]);
        }
    }
}

/// Names from the hook, directories included; names that would leave the directory are not
/// used; the stream must exist without `wait`.
#[test]
fn file_names() {
    struct Named;
    impl RecordHooks for Named {
        fn file_name(&self, stream: &str, index: u64, _: SystemTime, ext: &str) -> String {
            if index == 0 {
                format!("{stream}/part{index}.{ext}")
            } else {
                format!("../escape{index}.{ext}")
            }
        }
    }
    let hub = Hub::default();
    let base = dir("names");
    let mut cfg = RecordConfig::new(&base);
    cfg.wait = None;
    cfg.segment_duration = Some(Duration::from_secs(2));
    let rec = Recorder::with_hooks(hub.clone(), cfg.clone(), Named);
    assert_eq!(
        rec.start("live/n"),
        Err(HubError::NotFound),
        "no publisher, no wait"
    );
    cfg.wait = Some(Duration::from_secs(5));
    let rec = Recorder::with_hooks(hub.clone(), cfg, Named);
    rec.start("live/n").unwrap();
    rec.start("live/n").unwrap(); // already recorded: unchanged
    assert_eq!(rec.active(), ["live/n"]);
    publish(&hub, "live/n", &h264(), 2);
    rec.stop_all();
    assert!(rec.active().is_empty());
    drop(rec);
    // Wait for the writer to finish the files.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let first = base.join("live/n/part0.mp4");
        let others: Vec<_> = std::fs::read_dir(&base)
            .into_iter()
            .flatten()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| n.starts_with("live_n-") && n.ends_with("-1.mp4"))
            .collect();
        if first.exists() && others.len() == 1 {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "{others:?}");
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(!base.parent().unwrap().join("escape1.mp4").exists());
}
