//! Encrypted HLS (AES-128, `EXT-X-KEY`) of a hub stream, MPEG-TS and fMP4, plain and
//! Low-Latency, with key rotation and a key provider that only answers requests carrying a
//! header. Segments and parts fetched over HTTP decrypt (IV = media sequence number) to
//! valid media; with ffmpeg / ffprobe the live playlist itself plays (ffmpeg fetches and
//! applies the keys) and each decrypted segment decodes. Without ffmpeg / ffprobe the ffmpeg
//! parts are skipped; the playlist, key and decryption checks always run.

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    process::{Command, Stdio},
    sync::Arc,
    thread::JoinHandle,
    time::{Duration, Instant},
};

use only::{Engine, Listener};
use only_crypto::aes::Aes;
use only_http::{Context, Router, serve};
use only_media::{
    Hub, Packet, PeerInfo, Tracks,
    av::MILLISECOND,
    flv,
    hls::{Hls, HlsConfig, HlsEncryption, HlsKey, KeyProvider, SegmentFormat},
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

/// Key `n` is sixteen bytes of `n + 0x40`; requests need `X-Key-Token: secret`.
struct Keys;

fn key_of(n: u64) -> [u8; 16] {
    [n as u8 + 0x40; 16]
}

impl KeyProvider for Keys {
    fn key(&self, path: &str, n: u64) -> HlsKey {
        assert_eq!(path, "live/e");
        HlsKey::new(key_of(n))
    }

    fn authorize(&self, path: &str, n: u64, ctx: &Context) -> bool {
        assert_eq!(path, "live/e");
        let _ = n;
        ctx.header("x-key-token") == Some("secret")
    }
}

struct Server {
    hub: Hub,
    engine: Arc<Engine>,
    http: SocketAddr,
}

fn start(hls: HlsConfig) -> Server {
    let hub = Hub::default();
    let media = MediaHttp::new().hls(Hls::new(hub.clone(), hls));
    let app = Router::new().get("/*path", media);
    let engine = Arc::new(
        Engine::builder()
            .listen(Listener::tcp("127.0.0.1:0".parse().unwrap()).serve(serve(app)))
            .build()
            .unwrap(),
    );
    engine.start().unwrap();
    let http = engine.local_addrs()[0];
    Server { hub, engine, http }
}

/// Publishes the sample `rounds` times in a row, in real time, on `path`.
fn publish(
    hub: &Hub,
    path: &str,
    (tracks, pkts): (Tracks, Vec<Packet>),
    rounds: i64,
) -> JoinHandle<()> {
    let hub = hub.clone();
    let path = path.to_owned();
    std::thread::spawn(move || {
        let first = pkts.iter().map(|p| p.dts).min().unwrap();
        let last = pkts.iter().map(|p| p.dts).max().unwrap();
        let span = last - first + 40 * MILLISECOND;
        let p = hub.publish(&path, tracks, PeerInfo::default()).unwrap();
        let t0 = Instant::now();
        for round in 0..rounds {
            for pkt in &pkts {
                let at = pkt.dts - first + round * span;
                let wait = Duration::from_nanos(at.max(0) as u64).saturating_sub(t0.elapsed());
                std::thread::sleep(wait);
                let mut q = pkt.clone();
                q.dts += round * span;
                q.pts += round * span;
                p.write(q);
            }
        }
    })
}

/// GET with extra header lines, returning (status, head, body).
fn get(addr: SocketAddr, path: &str, headers: &str) -> (u16, String, Vec<u8>) {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
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

fn ffmpeg_present() -> bool {
    let ok = have("ffmpeg") && have("ffprobe");
    if !ok {
        eprintln!("ffmpeg/ffprobe not found: ffmpeg checks skipped");
    }
    ok
}

/// Runs ffmpeg decoding `input` (extra input options first) and returns its error log.
fn decode(input_opts: &[&str], input: &str, out_opts: &[&str]) -> String {
    let out = Command::new("ffmpeg")
        .args(["-nostdin", "-v", "error"])
        .args(input_opts)
        .args(["-i", input])
        .args(out_opts)
        .args(["-f", "null", "-"])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(out.status.success(), "{input}: {err}");
    err
}

fn probe_codecs(input_opts: &[&str], input: &str) -> String {
    let out = Command::new("ffprobe")
        .args(["-v", "error"])
        .args(input_opts)
        .args([
            "-show_entries",
            "stream=codec_name",
            "-of",
            "csv=p=0",
            input,
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{input}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// `(key number or None for METHOD=NONE, media URI)` in playlist order, plus the maps.
fn media(pl: &str) -> (Vec<(Option<u64>, String)>, Vec<String>) {
    let quoted = |l: &str| {
        l.split("URI=\"")
            .nth(1)
            .map(|r| r.split('"').next().unwrap().to_owned())
    };
    let (mut key, mut out, mut maps) = (None, Vec::new(), Vec::new());
    for l in pl.lines() {
        if l == "#EXT-X-KEY:METHOD=NONE" {
            key = None;
        } else if l.starts_with("#EXT-X-KEY:METHOD=AES-128,") {
            let uri = quoted(l).unwrap();
            let n = uri
                .strip_prefix("key-")
                .unwrap()
                .strip_suffix(".key")
                .unwrap();
            key = Some(n.parse().unwrap());
        } else if l.starts_with("#EXT-X-MAP:") {
            assert_eq!(key, None, "a map under a key: {pl}");
            maps.push(quoted(l).unwrap());
        } else if l.starts_with("#EXT-X-PART:") {
            out.push((key, quoted(l).unwrap()));
        } else if !l.starts_with('#') && !l.is_empty() {
            out.push((key, l.to_owned()));
        }
    }
    (out, maps)
}

fn check(format: SegmentFormat, parts: bool, ff: bool) {
    let mut cfg = HlsConfig::default();
    cfg.format = format;
    cfg.target_duration = Duration::from_secs(1);
    cfg.part_duration = parts.then(|| Duration::from_millis(250));
    cfg.play_wait = Some(Duration::from_secs(5));
    cfg.encryption = Some(HlsEncryption::new(Keys).rotate_every(2));
    let srv = start(cfg);
    let path = "live/e";
    let sample = flv_sample(include_bytes!("../testdata/h264_aac.flv"));
    let publisher = publish(&srv.hub, path, sample, 6);
    let (status, head, _) = get(srv.http, &format!("/{path}/index.m3u8"), "");
    assert_eq!(status, 200, "{head}");
    std::thread::sleep(Duration::from_secs(5));
    let (status, _, body) = get(srv.http, &format!("/{path}/index.m3u8"), "");
    assert_eq!(status, 200);
    let pl = String::from_utf8(body).unwrap();
    let (items, maps) = media(&pl);
    assert!(items.len() >= 3, "{pl}");
    let fmp4 = format == SegmentFormat::Fmp4;
    assert_eq!(fmp4, !maps.is_empty(), "{pl}");
    let mut keys_seen = Vec::new();
    let token = "X-Key-Token: secret\r\n";
    let dir = env!("CARGO_TARGET_TMPDIR");
    let init = maps.first().map(|m| {
        let (status, _, data) = get(srv.http, &format!("/{path}/{m}"), "");
        assert_eq!(status, 200);
        assert_eq!(&data[4..8], b"ftyp", "init segments are clear");
        data
    });
    for (i, (key, uri)) in items.iter().enumerate() {
        let n = key.unwrap_or_else(|| panic!("{uri} is not under a key: {pl}"));
        // seg-<s>.ext or part-<s>.<k>.ext: IV = <s>, key rotates every 2 segments.
        let seq: u64 = uri.split(['-', '.']).nth(1).unwrap().parse().unwrap();
        assert_eq!(n, seq / 2, "{uri}: {pl}");
        if !keys_seen.contains(&n) {
            keys_seen.push(n);
            // Refused without the token, answered with it.
            let k = format!("/{path}/key-{n}.key");
            assert_eq!(get(srv.http, &k, "").0, 403);
            let (status, head, raw) = get(srv.http, &k, token);
            assert_eq!(status, 200, "{head}");
            assert!(head.contains("application/octet-stream"), "{head}");
            assert!(head.contains("no-store"), "{head}");
            assert_eq!(raw, key_of(n));
        }
        let (status, _, data) = get(srv.http, &format!("/{path}/{uri}"), "");
        assert_eq!(status, 200, "{uri}");
        assert_eq!(data.len() % 16, 0);
        let mut plain = data;
        Aes::new128(&key_of(n))
            .decrypt_cbc_padded(&u128::from(seq).to_be_bytes(), &mut plain)
            .unwrap_or_else(|e| panic!("{uri}: {e}"));
        if fmp4 {
            let b = &plain[4..8];
            assert!(b == b"styp" || b == b"moof", "{uri}: {b:?}");
        } else {
            assert_eq!(plain[0], 0x47, "{uri}: TS sync byte");
            assert_eq!(plain.len() % 188, 0, "{uri}");
        }
        if ff && uri.starts_with("seg-") {
            let ext = if fmp4 { "mp4" } else { "ts" };
            let file = format!("{dir}/hlsenc-{}-{i}.{ext}", u8::from(parts));
            let mut all = init.clone().unwrap_or_default();
            all.extend_from_slice(&plain);
            std::fs::write(&file, &all).unwrap();
            let err = decode(&[], &file, &[]);
            assert!(err.trim().is_empty(), "{uri}: {err}");
            let _ = std::fs::remove_file(&file);
        }
    }
    assert_eq!(get(srv.http, &format!("/{path}/key-99.key"), token).0, 404);
    assert_eq!(get(srv.http, &format!("/{path}/key-x.key"), token).0, 404);
    assert_eq!(get(srv.http, "/live/none/key-0.key", token).0, 404);

    if ff {
        // ffmpeg plays the live playlist, fetching the keys with the header.
        let url = format!("http://{}/{path}/index.m3u8", srv.http);
        let headers = ["-headers", "X-Key-Token: secret\r\n"];
        let codecs = probe_codecs(&headers, &url);
        assert!(codecs.lines().any(|l| l.trim() == "h264"), "{codecs}");
        assert!(codecs.lines().any(|l| l.trim() == "aac"), "{codecs}");
        let err = decode(&headers, &url, &["-t", "3"]);
        assert!(err.trim().is_empty(), "{url}: {err}");
    }
    publisher.join().unwrap();
    srv.engine.shutdown();
}

#[test]
fn encrypted_ts() {
    check(SegmentFormat::MpegTs, false, ffmpeg_present());
}

#[test]
fn encrypted_ts_ll() {
    check(SegmentFormat::MpegTs, true, ffmpeg_present());
}

#[test]
fn encrypted_fmp4() {
    check(SegmentFormat::Fmp4, false, ffmpeg_present());
}

#[test]
fn encrypted_fmp4_ll() {
    check(SegmentFormat::Fmp4, true, ffmpeg_present());
}
