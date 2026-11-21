//! I-frame playlists, rendition reports and session keys over HTTP: two renditions (H.264 +
//! AAC and H.265 + AAC) published as separate hub streams under one multivariant playlist, in
//! MPEG-TS and in fMP4 (with LL-HLS parts). The multivariant playlist must list an
//! `EXT-X-I-FRAME-STREAM-INF` per rendition; every byte range of the I-frame playlists,
//! fetched with a `Range` request, must decode with ffmpeg on its own (with the init segment
//! in fMP4) to exactly one frame of the source; the LL-HLS media playlists must report the
//! other rendition's newest part, which a blocking reload then waits on; an encrypted
//! multivariant playlist must name each rendition's key with `EXT-X-SESSION-KEY` and still
//! play in ffmpeg. The ffmpeg checks are skipped when it is not installed.

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

use only::{Engine, Listener};
use only_crypto::aes::Aes;
use only_http::{Router, serve};
use only_media::{
    Hub, Packet, PeerInfo, Tracks,
    av::MILLISECOND,
    flv,
    hls::{
        EncryptionMethod, Hls, HlsConfig, HlsEncryption, Multivariant, RandomKeys, SegmentFormat,
        Variant,
    },
    http::MediaHttp,
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

/// Publishes the sample in a loop, in real time, on `path` until `stop`.
fn publish(
    hub: &Hub,
    path: &str,
    (tracks, pkts): (Tracks, Vec<Packet>),
    stop: Arc<AtomicBool>,
) -> JoinHandle<()> {
    let hub = hub.clone();
    let path = path.to_owned();
    std::thread::spawn(move || {
        let first = pkts.iter().map(|p| p.dts).min().unwrap();
        let last = pkts.iter().map(|p| p.dts).max().unwrap();
        let span = last - first + 40 * MILLISECOND;
        let p = hub.publish(&path, tracks, PeerInfo::default()).unwrap();
        let t0 = Instant::now();
        let mut round = 0;
        while !stop.load(Ordering::Acquire) {
            for pkt in &pkts {
                let at = pkt.dts - first + round * span;
                let wait = Duration::from_nanos(at.max(0) as u64).saturating_sub(t0.elapsed());
                std::thread::sleep(wait);
                let mut q = pkt.clone();
                q.dts += round * span;
                q.pts += round * span;
                p.write(q);
            }
            round += 1;
        }
    })
}

/// GET with extra header lines, returning (status, head, body).
fn get(addr: SocketAddr, path: &str, headers: &str) -> (u16, String, Vec<u8>) {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: x\r\n{headers}Connection: close\r\n\r\n"
    )
    .unwrap();
    let mut all = Vec::new();
    let _ = s.read_to_end(&mut all);
    let end = all.windows(4).position(|w| w == b"\r\n\r\n").expect("head");
    let head = String::from_utf8_lossy(&all[..end]).into_owned();
    let status = head[9..12].parse().unwrap();
    (status, head, all[end + 4..].to_vec())
}

fn have(tool: &str) -> bool {
    Command::new(tool)
        .arg("-version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// The MD5s of the video frames ffmpeg decodes from `input`, and its error output.
fn frame_md5s(input: &str) -> (Vec<String>, String) {
    let out = Command::new("ffmpeg")
        .args(["-nostdin", "-v", "error", "-i", input])
        .args(["-map", "0:v:0", "-f", "framemd5", "-"])
        .output()
        .unwrap();
    let md5s = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| l.rsplit(',').next().map(|m| m.trim().to_owned()))
        .collect();
    (md5s, String::from_utf8_lossy(&out.stderr).into_owned())
}

struct Server {
    engine: Arc<Engine>,
    http: SocketAddr,
    stop: Arc<AtomicBool>,
    publishers: Vec<JoinHandle<()>>,
}

impl Server {
    fn end(self) {
        self.stop.store(true, Ordering::Release);
        for p in self.publishers {
            p.join().unwrap();
        }
        self.engine.shutdown();
    }
}

const SOURCES: [(&str, &[u8]); 2] = [
    ("live/cam_avc", include_bytes!("../testdata/h264_aac.flv")),
    ("live/cam_hevc", include_bytes!("../testdata/h265_aac.flv")),
];

/// Serves `cfg` with both renditions published under the multivariant playlist `live/cam`.
fn start(cfg: HlsConfig) -> Server {
    start_on(cfg, "127.0.0.1:0".parse().unwrap())
}

/// [`start`] on `addr`.
fn start_on(cfg: HlsConfig, addr: SocketAddr) -> Server {
    let hub = Hub::default();
    let hls = Hls::new(hub.clone(), cfg);
    let mut m = Multivariant::new();
    for (path, _) in SOURCES {
        m.variants.push(Variant::new(path));
    }
    hls.add_multivariant("live/cam", m);
    let app = Router::new().get("/*path", MediaHttp::new().hls(hls));
    let engine = Arc::new(
        Engine::builder()
            .listen(Listener::tcp(addr).serve(serve(app)))
            .build()
            .unwrap(),
    );
    engine.start().unwrap();
    let http = engine.local_addrs()[0];
    let stop = Arc::new(AtomicBool::new(false));
    let publishers = SOURCES
        .iter()
        .map(|(path, data)| publish(&hub, path, flv_sample(data), stop.clone()))
        .collect();
    Server {
        engine,
        http,
        stop,
        publishers,
    }
}

fn config(format: SegmentFormat, parts: bool) -> HlsConfig {
    let mut cfg = HlsConfig::default();
    cfg.format = format;
    cfg.target_duration = Duration::from_secs(1);
    cfg.part_duration = parts.then(|| Duration::from_millis(250));
    cfg.play_wait = Some(Duration::from_secs(5));
    cfg.iframe_playlist = true;
    cfg
}

/// `(len, offset, uri)` of each entry of an I-frame playlist.
fn entries(pl: &str) -> Vec<(usize, usize, String)> {
    let lines: Vec<&str> = pl.lines().collect();
    let mut out = Vec::new();
    for (i, l) in lines.iter().enumerate() {
        let Some(r) = l.strip_prefix("#EXT-X-BYTERANGE:") else {
            continue;
        };
        assert!(lines[i - 1].starts_with("#EXTINF:"), "{pl}");
        let (len, off) = r.split_once('@').unwrap();
        out.push((
            len.parse().unwrap(),
            off.parse().unwrap(),
            lines[i + 1].to_owned(),
        ));
    }
    out
}

fn check_iframes(format: SegmentFormat, parts: bool) {
    let ff = have("ffmpeg");
    let fmp4 = format == SegmentFormat::Fmp4;
    let srv = start(config(format, parts));
    let (status, head, _) = get(srv.http, "/live/cam.m3u8", "");
    assert_eq!(status, 200, "{head}");
    std::thread::sleep(Duration::from_secs(5));
    let (_, _, body) = get(srv.http, "/live/cam.m3u8", "");
    let master = String::from_utf8(body).unwrap();
    let iframe_uris: Vec<String> = master
        .lines()
        .filter_map(|l| l.strip_prefix("#EXT-X-I-FRAME-STREAM-INF:"))
        .map(|l| {
            l.split("URI=\"")
                .nth(1)
                .unwrap()
                .trim_end_matches('"')
                .to_owned()
        })
        .collect();
    assert_eq!(
        iframe_uris,
        ["cam_avc/iframes.m3u8", "cam_hevc/iframes.m3u8"],
        "{master}"
    );
    for (k, ((path, data), uri)) in SOURCES.iter().zip(&iframe_uris).enumerate() {
        let source = if ff {
            let file = format!("{}/iframes-src-{k}.flv", env!("CARGO_TARGET_TMPDIR"));
            std::fs::write(&file, data).unwrap();
            frame_md5s(&file).0
        } else {
            Vec::new()
        };
        let (status, _, body) = get(srv.http, &format!("/live/{uri}"), "");
        assert_eq!(status, 200);
        let pl = String::from_utf8(body).unwrap();
        assert!(pl.contains("#EXT-X-I-FRAMES-ONLY\n"), "{pl}");
        let list = entries(&pl);
        assert!(list.len() >= 3, "{pl}");
        let init = fmp4.then(|| {
            let m = pl
                .lines()
                .find_map(|l| l.strip_prefix("#EXT-X-MAP:URI=\""))
                .unwrap()
                .trim_end_matches('"');
            let (status, _, data) = get(srv.http, &format!("/{path}/{m}"), "");
            assert_eq!(status, 200);
            data
        });
        for (i, (len, off, seg)) in list.iter().enumerate() {
            let range = format!("Range: bytes={off}-{}\r\n", off + len - 1);
            let (status, head, bytes) = get(srv.http, &format!("/{path}/{seg}"), &range);
            assert_eq!(status, 206, "{seg} {range}: {head}");
            assert!(
                head.to_ascii_lowercase()
                    .contains(&format!("content-range: bytes {off}-{}/", off + len - 1)),
                "{head}"
            );
            assert_eq!(bytes.len(), *len);
            if !ff {
                continue;
            }
            let ext = if fmp4 { "mp4" } else { "ts" };
            let file = format!(
                "{}/iframe-{}-{k}-{i}.{ext}",
                env!("CARGO_TARGET_TMPDIR"),
                u8::from(parts)
            );
            let mut all = init.clone().unwrap_or_default();
            all.extend_from_slice(&bytes);
            std::fs::write(&file, &all).unwrap();
            let (got, err) = frame_md5s(&file);
            assert!(err.trim().is_empty(), "{seg} {range}: {err}");
            assert_eq!(got.len(), 1, "{seg} {range}: {got:?}");
            assert!(
                source.contains(&got[0]),
                "{seg} {range}: not a source frame"
            );
            let _ = std::fs::remove_file(&file);
        }
    }
    if parts {
        // Each LL-HLS media playlist reports the other rendition, its URI carrying the
        // request's query (an auth token; the `_HLS_` directives of a blocking reload left
        // out); a blocking reload of that rendition at the next part, made as a player makes
        // it (the report's URI plus `_HLS_msn` / `_HLS_part`), is answered.
        let (_, _, body) = get(
            srv.http,
            "/live/cam_avc/index.m3u8?token=t0k&_HLS_msn=0",
            "",
        );
        let pl = String::from_utf8(body).unwrap();
        let report = pl
            .lines()
            .find_map(|l| l.strip_prefix("#EXT-X-RENDITION-REPORT:"))
            .unwrap_or_else(|| panic!("no rendition report: {pl}"));
        assert!(
            report.starts_with("URI=\"../cam_hevc/index.m3u8?token=t0k\",LAST-MSN="),
            "{report}"
        );
        let num = |k: &str| -> u64 {
            report
                .split(',')
                .find_map(|a| a.strip_prefix(k))
                .unwrap()
                .parse()
                .unwrap()
        };
        let (msn, part) = (num("LAST-MSN="), num("LAST-PART="));
        let t = Instant::now();
        let q = format!(
            "/live/cam_hevc/index.m3u8?token=t0k&_HLS_msn={msn}&_HLS_part={}",
            part + 1
        );
        let (status, _, body) = get(srv.http, &q, "");
        assert_eq!(status, 200);
        assert!(t.elapsed() < Duration::from_secs(3));
        let pl = String::from_utf8(body).unwrap();
        assert!(
            pl.contains("URI=\"../cam_avc/index.m3u8?token=t0k\""),
            "{pl}"
        );
    } else {
        let (_, _, body) = get(srv.http, "/live/cam_avc/index.m3u8", "");
        assert!(
            !String::from_utf8(body)
                .unwrap()
                .contains("RENDITION-REPORT")
        );
    }
    if ff {
        // The multivariant playlist with its I-frame streams still plays.
        let url = format!("http://{}/live/cam.m3u8", srv.http);
        let out = Command::new("ffprobe")
            .args([
                "-v",
                "error",
                "-show_entries",
                "stream=codec_name",
                "-of",
                "csv=p=0",
            ])
            .arg(&url)
            .output()
            .unwrap();
        let codecs = String::from_utf8_lossy(&out.stdout);
        for c in ["h264", "hevc", "aac"] {
            assert!(codecs.lines().any(|l| l.trim() == c), "{codecs}");
        }
    }
    srv.end();
}

#[test]
fn iframes_mpegts() {
    check_iframes(SegmentFormat::MpegTs, false);
}

#[test]
fn iframes_fmp4_low_latency() {
    check_iframes(SegmentFormat::Fmp4, true);
}

/// SAMPLE-AES renditions: one `EXT-X-SESSION-KEY` per rendition naming its media playlist's
/// key (and IV in MPEG-TS), and the playlist plays in ffmpeg.
#[test]
fn session_keys() {
    for format in [SegmentFormat::MpegTs, SegmentFormat::Fmp4] {
        let mut cfg = config(format, false);
        cfg.encryption = Some(
            HlsEncryption::new(RandomKeys::new().unwrap()).method(EncryptionMethod::SampleAes),
        );
        let srv = start(cfg);
        let (status, _, body) = get(srv.http, "/live/cam.m3u8", "");
        assert_eq!(status, 200);
        let master = String::from_utf8(body).unwrap();
        let keys: Vec<&str> = master
            .lines()
            .filter(|l| l.starts_with("#EXT-X-SESSION-KEY:METHOD=SAMPLE-AES,URI="))
            .collect();
        assert_eq!(keys.len(), 2, "{master}");
        for ((path, _), k) in SOURCES.iter().zip(&keys) {
            let name = path.trim_start_matches("live/");
            assert!(k.contains(&format!("URI=\"{name}/key-0.key\"")), "{k}");
            let (_, _, body) = get(srv.http, &format!("/{path}/index.m3u8"), "");
            let media = String::from_utf8(body).unwrap();
            let attrs = k
                .trim_start_matches("#EXT-X-SESSION-KEY:")
                .replace(&format!("{name}/"), "");
            assert!(
                media.contains(&format!("#EXT-X-KEY:{attrs}\n")),
                "{k}\n{media}"
            );
            let (status, _, key) = get(srv.http, &format!("/{path}/key-0.key"), "");
            assert_eq!((status, key.len()), (200, 16));
        }
        if have("ffmpeg") {
            let url = format!("http://{}/live/cam.m3u8", srv.http);
            let out = Command::new("ffmpeg")
                .args(["-nostdin", "-v", "error", "-i", &url, "-t", "2"])
                .args(["-map", "0:v:0", "-f", "null", "-"])
                .output()
                .unwrap();
            let err = String::from_utf8_lossy(&out.stderr);
            assert!(
                out.status.success() && err.trim().is_empty(),
                "{url}: {err}"
            );
        }
        srv.end();
    }
}

/// AES-128 renditions: the I-frame playlists list each keyframe as a resource of its own
/// (`iframe-<n>`, no byte range) after the `EXT-X-KEY` of its segment; each, decrypted with
/// that key and the IV of its media sequence number, decodes with ffmpeg (with the clear init
/// segment in fMP4) to exactly one frame of the source; ffmpeg also plays the I-frame playlist
/// itself (decrypting as RFC 8216 says), one source frame per entry, and the multivariant
/// playlist with its I-frame streams.
fn check_aes128_iframes(format: SegmentFormat) {
    let ff = have("ffmpeg");
    let fmp4 = format == SegmentFormat::Fmp4;
    let mut cfg = config(format, false);
    cfg.encryption = Some(HlsEncryption::new(RandomKeys::new().unwrap()).rotate_every(2));
    let srv = start(cfg);
    let (status, head, _) = get(srv.http, "/live/cam.m3u8", "");
    assert_eq!(status, 200, "{head}");
    std::thread::sleep(Duration::from_secs(6));
    let (_, _, body) = get(srv.http, "/live/cam.m3u8", "");
    let master = String::from_utf8(body).unwrap();
    assert_eq!(
        master.matches("#EXT-X-I-FRAME-STREAM-INF:").count(),
        2,
        "{master}"
    );
    let ext = if fmp4 { ".m4s" } else { ".ts" };
    for (k, (path, data)) in SOURCES.iter().enumerate() {
        let source = if ff {
            let file = format!("{}/aes-iframes-src-{k}.flv", env!("CARGO_TARGET_TMPDIR"));
            std::fs::write(&file, data).unwrap();
            frame_md5s(&file).0
        } else {
            Vec::new()
        };
        let (status, _, body) = get(srv.http, &format!("/{path}/iframes.m3u8"), "");
        assert_eq!(status, 200);
        let pl = String::from_utf8(body).unwrap();
        assert!(pl.contains("#EXT-X-I-FRAMES-ONLY\n"), "{pl}");
        assert!(!pl.contains("BYTERANGE"), "{pl}");
        let msn: u64 = pl
            .lines()
            .find_map(|l| l.strip_prefix("#EXT-X-MEDIA-SEQUENCE:"))
            .unwrap()
            .parse()
            .unwrap();
        let init = fmp4.then(|| {
            let m = pl
                .lines()
                .find_map(|l| l.strip_prefix("#EXT-X-MAP:URI=\""))
                .unwrap()
                .trim_end_matches('"');
            get(srv.http, &format!("/{path}/{m}"), "").2
        });
        // (key URI, uri) per entry, in order.
        let mut key = None;
        let mut list = Vec::new();
        let mut lines = pl.lines();
        while let Some(l) = lines.next() {
            if let Some(u) = l.strip_prefix("#EXT-X-KEY:METHOD=AES-128,URI=\"") {
                key = Some(u.trim_end_matches('"').to_owned());
            } else if l.starts_with("#EXTINF:") {
                list.push((key.clone().expect("a key first"), lines.next().unwrap()));
            }
        }
        assert!(list.len() >= 4, "{pl}");
        let keys: std::collections::BTreeSet<&String> = list.iter().map(|(k, _)| k).collect();
        assert!(keys.len() >= 2, "rotated keys: {pl}");
        for (i, (key_uri, uri)) in list.iter().enumerate() {
            let n = msn + i as u64;
            assert_eq!(*uri, format!("iframe-{n}{ext}"), "{pl}");
            let (status, _, key) = get(srv.http, &format!("/{path}/{key_uri}"), "");
            assert_eq!((status, key.len()), (200, 16));
            let (status, head, cipher) = get(srv.http, &format!("/{path}/{uri}"), "");
            assert_eq!(status, 200, "{uri}: {head}");
            assert_eq!(cipher.len() % 16, 0);
            let mut plain = cipher;
            Aes::new128(&key.try_into().unwrap())
                .decrypt_cbc_padded(&u128::from(n).to_be_bytes(), &mut plain)
                .expect("decrypts with the IV of its number");
            if fmp4 {
                assert_eq!(&plain[4..8], b"moof");
            } else {
                assert_eq!(plain[..3], [0x47, 0x40, 0x00], "starts with the PAT");
            }
            if !ff {
                continue;
            }
            let file = format!(
                "{}/aes-iframe-{k}-{i}.{}",
                env!("CARGO_TARGET_TMPDIR"),
                if fmp4 { "mp4" } else { "ts" }
            );
            let mut all = init.clone().unwrap_or_default();
            all.extend_from_slice(&plain);
            std::fs::write(&file, &all).unwrap();
            let (got, err) = frame_md5s(&file);
            assert!(err.trim().is_empty(), "{uri}: {err}");
            assert_eq!(got.len(), 1, "{uri}: {got:?}");
            assert!(source.contains(&got[0]), "{uri}: not a source frame");
            let _ = std::fs::remove_file(&file);
        }
        if ff {
            // ffmpeg reads the I-frame playlist as a media playlist: it fetches the keys and
            // decrypts every entry with the IV of its media sequence number. A snapshot of it
            // as a VOD playlist (absolute URIs, `EXT-X-ENDLIST`), as ffmpeg would otherwise
            // read a live one from its end in real time, probing for the audio an I-frame
            // playlist does not carry. ffmpeg reports the continuity counters jumping from
            // one I-frame to the next as corrupt packets (it reads them as one stream): the
            // frames are whole.
            let base = format!("http://{}/{path}/", srv.http);
            let vod: String = pl
                .lines()
                .map(|l| {
                    if l.starts_with("iframe-") || l.starts_with("init-") {
                        format!("{base}{l}\n")
                    } else {
                        format!("{}\n", l.replace("URI=\"", &format!("URI=\"{base}")))
                    }
                })
                .chain(std::iter::once("#EXT-X-ENDLIST\n".to_owned()))
                .collect();
            let file = format!("{}/aes-iframes-{k}.m3u8", env!("CARGO_TARGET_TMPDIR"));
            std::fs::write(&file, vod).unwrap();
            let out = Command::new("ffmpeg")
                .args(["-nostdin", "-v", "error"])
                .args(["-protocol_whitelist", "file,http,tcp,crypto"])
                .args(["-i", &file, "-map", "0:v:0", "-f", "framemd5", "-"])
                .output()
                .unwrap();
            let got: Vec<String> = String::from_utf8_lossy(&out.stdout)
                .lines()
                .filter(|l| !l.starts_with('#'))
                .filter_map(|l| l.rsplit(',').next().map(|m| m.trim().to_owned()))
                .collect();
            let err = String::from_utf8_lossy(&out.stderr);
            let other: Vec<&str> = err
                .lines()
                .filter(|l| !l.contains("Packet corrupt"))
                .collect();
            assert!(other.is_empty(), "{file}: {err}");
            assert_eq!(got.len(), list.len(), "{file}: {err}");
            for m in &got {
                assert!(source.contains(m), "{file}: not a source frame");
            }
        }
    }
    if ff {
        let url = format!("http://{}/live/cam.m3u8", srv.http);
        let out = Command::new("ffmpeg")
            .args(["-nostdin", "-v", "error", "-i", &url, "-t", "2"])
            .args(["-map", "0:v:0", "-f", "null", "-"])
            .output()
            .unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success() && err.trim().is_empty(),
            "{url}: {err}"
        );
    }
    srv.end();
}

#[test]
fn iframes_aes128_mpegts() {
    check_aes128_iframes(SegmentFormat::MpegTs);
}

#[test]
fn iframes_aes128_fmp4() {
    check_aes128_iframes(SegmentFormat::Fmp4);
}

/// For `tools/interop/media/hls-iframes.sh`: serves the AES-128 renditions with I-frame
/// playlists (keys rotated every two segments, CORS open) in MPEG-TS on the first address of
/// `ONLY_HLS_IFRAMES_ADDRS` and in fMP4 on the second, for `ONLY_HLS_IFRAMES_SECS` seconds
/// (60 by default); with `ONLY_HLS_IFRAMES_CLEAR` set, unencrypted (byte-range I-frames).
#[test]
#[ignore = "a server for the browser interop script"]
fn serve_aes128_iframes() {
    let addrs = std::env::var("ONLY_HLS_IFRAMES_ADDRS")
        .unwrap_or_else(|_| "127.0.0.1:9551,127.0.0.1:9552".to_owned());
    let secs: u64 = std::env::var("ONLY_HLS_IFRAMES_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(60);
    let servers: Vec<Server> = addrs
        .split(',')
        .zip([SegmentFormat::MpegTs, SegmentFormat::Fmp4])
        .map(|(addr, format)| {
            let mut cfg = config(format, false);
            if std::env::var_os("ONLY_HLS_IFRAMES_CLEAR").is_none() {
                cfg.encryption =
                    Some(HlsEncryption::new(RandomKeys::new().unwrap()).rotate_every(2));
            }
            cfg.cors_origin = Some("*".to_owned());
            cfg.idle_timeout = Duration::from_secs(secs);
            start_on(cfg, addr.parse().unwrap())
        })
        .collect();
    println!("READY");
    std::thread::sleep(Duration::from_secs(secs));
    for s in servers {
        s.end();
    }
}
