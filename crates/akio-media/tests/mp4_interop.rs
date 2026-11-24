#![cfg(unix)]
//! MP4 files ffmpeg writes, cut into HLS segments by `akio_media::mp4` and read back by
//! ffmpeg / ffprobe: H.264 + AAC (`moov` at the back, B-frames), H.265 + AAC (`moov` at the
//! front) and H.264 + Opus, each ten seconds with a keyframe every two. The file is read
//! through `Locator` and range reads only, as a server does; every segment, as fMP4 (init +
//! fragment) and as MPEG-TS, must decode without errors and start with a keyframe, and the
//! VOD playlists of both must play to the end with every video frame. Without ffmpeg /
//! ffprobe the test is skipped.

use std::{
    fs::{self, File},
    os::unix::fs::FileExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use akio_media::{
    av::SECOND,
    fmp4,
    mp4::{Limits, Locator, Movie, Plan},
    mpegts,
};

fn have(tool: &str) -> bool {
    Command::new(tool)
        .arg("-version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("akio-mp4-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn ffmpeg(args: &[&str]) {
    let out = Command::new("ffmpeg")
        .args(["-hide_banner", "-loglevel", "error", "-y"])
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "ffmpeg {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Decodes `input` to nothing; returns ffmpeg's errors (empty when clean).
fn decode_errors(input: &Path) -> String {
    let out = Command::new("ffmpeg")
        .args(["-hide_banner", "-v", "error", "-i"])
        .arg(input)
        .args(["-f", "null", "-"])
        .output()
        .unwrap();
    let mut e = String::from_utf8_lossy(&out.stderr).into_owned();
    if !out.status.success() {
        e.push_str("(failed)");
    }
    e
}

/// `(codec, frames, first frame is a keyframe)` of the video stream of `input`.
fn video_frames(input: &Path) -> (String, usize, bool) {
    let out = Command::new("ffprobe")
        .args(["-v", "error", "-select_streams", "v:0", "-show_entries"])
        .args(["packet=flags:stream=codec_name", "-of", "compact=p=0:nk=1"])
        .arg(input)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    let mut codec = String::new();
    let mut flags = Vec::new();
    for l in text.lines() {
        if l.starts_with('K') || l.starts_with('_') {
            flags.push(l.to_owned());
        } else if !l.is_empty() {
            codec = l.to_owned();
        }
    }
    let key = flags.first().is_some_and(|f| f.starts_with('K'));
    (codec, flags.len(), key)
}

/// Reads `path` as a server does: the moov located by header reads, then read whole.
fn open(path: &Path) -> (File, Movie) {
    let f = File::open(path).unwrap();
    let size = f.metadata().unwrap().len();
    let limits = Limits::default();
    let mut loc = Locator::new(size, &limits);
    let mut buf = [0u8; 16];
    let at = loop {
        let (off, len) = loc.next_read();
        f.read_exact_at(&mut buf[..len], off).unwrap();
        if let Some(at) = loc.feed(&buf[..len]).unwrap() {
            break at;
        }
    };
    let mut moov = vec![0u8; at.size as usize];
    f.read_exact_at(&mut moov, at.offset).unwrap();
    let m = Movie::parse(&moov, &at, &limits).unwrap();
    (f, m)
}

#[test]
fn ffmpeg_files_cut_into_hls() {
    if !have("ffmpeg") || !have("ffprobe") {
        eprintln!("ffmpeg/ffprobe not found: skipped");
        return;
    }
    let cases: [(&str, &[&str], &str); 3] = [
        (
            "h264_aac",
            &[
                "-c:v",
                "libx264",
                "-preset",
                "veryfast",
                "-bf",
                "2",
                "-g",
                "50",
                "-keyint_min",
                "50",
                "-sc_threshold",
                "0",
                "-c:a",
                "aac",
                "-b:a",
                "64k",
            ],
            "h264",
        ),
        (
            "h265_aac",
            &[
                "-c:v",
                "libx265",
                "-preset",
                "veryfast",
                "-tag:v",
                "hvc1",
                "-x265-params",
                "keyint=50:min-keyint=50:scenecut=0:bframes=2:log-level=error",
                "-c:a",
                "aac",
                "-movflags",
                "+faststart",
            ],
            "hevc",
        ),
        (
            "h264_opus",
            &[
                "-c:v",
                "libx264",
                "-preset",
                "veryfast",
                "-g",
                "50",
                "-keyint_min",
                "50",
                "-sc_threshold",
                "0",
                "-c:a",
                "libopus",
                "-b:a",
                "32k",
            ],
            "h264",
        ),
    ];
    for (name, codecs, vcodec) in cases {
        let d = dir(name);
        let src = d.join("src.mp4");
        let mut args = vec![
            "-f",
            "lavfi",
            "-i",
            "testsrc2=size=320x240:rate=25",
            "-f",
            "lavfi",
            "-i",
            "sine=frequency=440:sample_rate=48000",
            "-t",
            "10",
            "-pix_fmt",
            "yuv420p",
        ];
        args.extend_from_slice(codecs);
        args.push(src.to_str().unwrap());
        ffmpeg(&args);

        let (file, movie) = open(&src);
        let plan = Plan::new(&movie, 2 * SECOND).unwrap();
        assert_eq!(plan.len(), 5, "{name}: a segment a keyframe");
        let tracks = movie.av_tracks();
        let mut fmux = fmp4::Muxer::new(&tracks);
        let init = fmux.init_segment().to_vec();
        fs::write(d.join("init.mp4"), &init).unwrap();
        let mut total = 0;
        for i in 0..plan.len() {
            let seg = plan.segment(&movie, i);
            let reads: Vec<(u64, Vec<u8>)> = seg
                .byte_ranges(&movie, 4096)
                .into_iter()
                .map(|r| {
                    let mut b = vec![0u8; (r.end - r.start) as usize];
                    file.read_exact_at(&mut b, r.start).unwrap();
                    (r.start, b)
                })
                .collect();
            let parts: Vec<(u64, &[u8])> = reads.iter().map(|(o, b)| (*o, &b[..])).collect();
            let frames = seg.samples[0].len();
            total += frames;

            let mut m4s = Vec::new();
            seg.write_fmp4(&movie, &parts, &mut fmux, &mut m4s).unwrap();
            fs::write(d.join(format!("{i}.m4s")), &m4s).unwrap();
            let whole = d.join(format!("whole{i}.mp4"));
            fs::write(&whole, [&init[..], &m4s].concat()).unwrap();

            let mut ts = Vec::new();
            seg.write_ts(&movie, &parts, &mut mpegts::Muxer::new(&tracks), &mut ts)
                .unwrap();
            let tsp = d.join(format!("{i}.ts"));
            fs::write(&tsp, &ts).unwrap();

            for p in [&whole, &tsp] {
                assert_eq!(decode_errors(p), "", "{name} segment {i} {}", p.display());
                let (codec, n, key) = video_frames(p);
                assert_eq!(codec, vcodec, "{name} {}", p.display());
                assert_eq!(n, frames, "{name} segment {i} {}", p.display());
                assert!(key, "{name} segment {i} starts with a keyframe");
            }
        }
        assert_eq!(total, 250, "{name}");
        let fmp4_pl = d.join("fmp4.m3u8");
        fs::write(
            &fmp4_pl,
            plan.vod_playlist(Some("init.mp4"), |i| format!("{i}.m4s")),
        )
        .unwrap();
        let ts_pl = d.join("ts.m3u8");
        fs::write(&ts_pl, plan.vod_playlist(None, |i| format!("{i}.ts"))).unwrap();
        for pl in [&fmp4_pl, &ts_pl] {
            assert_eq!(decode_errors(pl), "", "{name} {}", pl.display());
            let (_, n, key) = video_frames(pl);
            assert_eq!(n, 250, "{name} {}", pl.display());
            assert!(key);
        }
        let _ = fs::remove_dir_all(&d);
    }
}
