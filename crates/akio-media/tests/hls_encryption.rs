//! Encrypted HLS (AES-128, `EXT-X-KEY`) of a hub stream, MPEG-TS and fMP4, plain and
//! Low-Latency, with key rotation and a key provider that only answers requests carrying a
//! header. Segments and parts fetched over HTTP decrypt (IV = media sequence number) to
//! valid media; with ffmpeg / ffprobe the live playlist itself plays (ffmpeg fetches and
//! applies the keys) and each decrypted segment decodes. Without ffmpeg / ffprobe the ffmpeg
//! parts are skipped; the playlist, key and decryption checks always run.
//!
//! SAMPLE-AES (MPEG-TS with Apple's sample encryption, fMP4 with `cbcs`): ffmpeg plays the
//! live playlist and every video frame it decodes is one of the source's (frame MD5s), while
//! the segments read as plain media do not decode to them; the TS segments carry the
//! SAMPLE-AES stream types and the fMP4 init segment `encv` / `enca` with `cbcs`.

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    process::{Command, Stdio},
    sync::Arc,
    thread::JoinHandle,
    time::{Duration, Instant},
};

use akio::{Engine, Listener};
use akio_crypto::aes::Aes;
use akio_http::{Context, Router, serve};
use akio_media::{
    Hub, Packet, PeerInfo, Tracks,
    av::MILLISECOND,
    flv,
    hls::{EncryptionMethod, Hls, HlsConfig, HlsEncryption, HlsKey, KeyProvider, SegmentFormat},
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

/// The MD5s of the video frames ffmpeg decodes from `input`.
fn frame_md5s(input_opts: &[&str], input: &str, out_opts: &[&str]) -> Vec<String> {
    let out = Command::new("ffmpeg")
        .args(["-nostdin", "-v", "error"])
        .args(input_opts)
        .args(["-i", input])
        .args(out_opts)
        .args(["-map", "0:v:0", "-f", "framemd5", "-"])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| l.rsplit(',').next().map(|m| m.trim().to_owned()))
        .collect()
}

/// Removes emulation prevention bytes.
fn unescape(n: &[u8]) -> Vec<u8> {
    let (mut out, mut zeros) = (Vec::with_capacity(n.len()), 0);
    for &b in n {
        if zeros >= 2 && b == 3 {
            zeros = 0;
            continue;
        }
        zeros = if b == 0 { zeros + 1 } else { 0 };
        out.push(b);
    }
    out
}

fn escape(n: &[u8]) -> Vec<u8> {
    let (mut out, mut zeros) = (Vec::with_capacity(n.len() + 8), 0);
    for &b in n {
        if zeros >= 2 && b <= 3 {
            out.push(3);
            zeros = 0;
        }
        out.push(b);
        zeros = if b == 0 { zeros + 1 } else { 0 };
    }
    out
}

/// Decrypts the H.264 slices and AAC frames of a SAMPLE-AES MPEG-TS segment (Apple's
/// format, implemented here on its own): (slices, AAC payloads).
fn decrypt_sample_aes_ts(ts: &[u8], aes: &Aes, iv: [u8; 16]) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    // PES payloads of the video (0x100) and audio (0x101) PIDs.
    let (mut video, mut audio): (Vec<Vec<u8>>, Vec<Vec<u8>>) = (Vec::new(), Vec::new());
    for p in ts.chunks(188) {
        let pid = (u16::from(p[1] & 0x1f) << 8) | u16::from(p[2]);
        let es = match pid {
            0x100 => &mut video,
            0x101 => &mut audio,
            _ => continue,
        };
        let mut off = 4;
        if p[3] & 0x20 != 0 {
            off += 1 + usize::from(p[4]);
        }
        let mut payload = &p[off..];
        if p[1] & 0x40 != 0 {
            payload = &payload[9 + usize::from(payload[8])..];
            es.push(Vec::new());
        }
        if let Some(cur) = es.last_mut() {
            cur.extend_from_slice(payload);
        }
    }
    let mut slices = Vec::new();
    for pes in &video {
        let mut starts = Vec::new();
        for i in 0..pes.len().saturating_sub(2) {
            if pes[i..i + 3] == [0, 0, 1] {
                starts.push(i + 3);
            }
        }
        for (k, &s) in starts.iter().enumerate() {
            let mut e = starts.get(k + 1).map_or(pes.len(), |&n| n - 3);
            while e > s && pes[e - 1] == 0 {
                e -= 1;
            }
            let n = &pes[s..e];
            if !matches!(n[0] & 0x1f, 1 | 5) {
                continue;
            }
            if n.len() <= 48 {
                slices.push(n.to_vec());
                continue;
            }
            let mut r = unescape(n);
            let mut at = 32;
            let mut v = iv;
            while r.len().saturating_sub(at) > 16 {
                aes.decrypt_cbc(&mut v, &mut r[at..at + 16]).unwrap();
                at += 160;
            }
            slices.push(escape(&r));
        }
    }
    let mut frames = Vec::new();
    for pes in &audio {
        let mut b = &pes[..];
        while b.len() >= 7 && b[0] == 0xff {
            let len =
                (usize::from(b[3] & 3) << 11) | (usize::from(b[4]) << 3) | usize::from(b[5] >> 5);
            let mut f = b[7..len].to_vec();
            if f.len() >= 32 {
                let end = 16 + (f.len() - 16) / 16 * 16;
                let mut v = iv;
                aes.decrypt_cbc(&mut v, &mut f[16..end]).unwrap();
            }
            frames.push(f);
            b = &b[len..];
        }
    }
    (slices, frames)
}

fn check_sample_aes(format: SegmentFormat, parts: bool, ff: bool) {
    let fmp4 = format == SegmentFormat::Fmp4;
    let sample = flv_sample(include_bytes!("../testdata/h264_aac.flv"));
    let src_slices: Vec<Vec<u8>> = sample
        .1
        .iter()
        .filter(|p| p.track == 0)
        .flat_map(|p| {
            let mut v = Vec::new();
            let mut d = &p.data[..];
            while d.len() >= 4 {
                let n = u32::from_be_bytes([d[0], d[1], d[2], d[3]]) as usize;
                if matches!(d[4] & 0x1f, 1 | 5) {
                    v.push(d[4..4 + n].to_vec());
                }
                d = &d[4 + n..];
            }
            v
        })
        .collect();
    let src_audio: Vec<Vec<u8>> = sample
        .1
        .iter()
        .filter(|p| p.track == 1)
        .map(|p| p.data.clone())
        .collect();
    let dir = env!("CARGO_TARGET_TMPDIR");
    let path = "live/e";
    let source = if ff {
        frame_md5s(
            &[],
            concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/h264_aac.flv"),
            &[],
        )
    } else {
        Vec::new()
    };
    // With keys rotating every 2 segments; then (for ffmpeg, which cannot follow a key
    // change at the packets it reads ahead) with one key.
    for rotate in [2, 0] {
        if rotate == 0 && !ff {
            break;
        }
        let mut cfg = HlsConfig::default();
        cfg.format = format;
        cfg.target_duration = Duration::from_secs(1);
        cfg.part_duration = parts.then(|| Duration::from_millis(250));
        cfg.play_wait = Some(Duration::from_secs(5));
        cfg.encryption = Some(
            HlsEncryption::new(Keys)
                .rotate_every(rotate)
                .method(EncryptionMethod::SampleAes),
        );
        let srv = start(cfg);
        let publisher = publish(&srv.hub, path, sample.clone(), 6);
        let (status, head, _) = get(srv.http, &format!("/{path}/index.m3u8"), "");
        assert_eq!(status, 200, "{head}");
        std::thread::sleep(Duration::from_secs(5));
        let (status, _, body) = get(srv.http, &format!("/{path}/index.m3u8"), "");
        assert_eq!(status, 200);
        let pl = String::from_utf8(body).unwrap();
        assert!(!pl.contains("AES-128"), "{pl}");
        // (key number, IV) of each segment.
        let mut cur: Option<(u64, Option<[u8; 16]>)> = None;
        let mut segs = Vec::new();
        for l in pl.lines() {
            if let Some(rest) = l.strip_prefix("#EXT-X-KEY:METHOD=SAMPLE-AES,URI=\"key-") {
                let n: u64 = rest.split('.').next().unwrap().parse().unwrap();
                let iv = rest
                    .split(",IV=0x")
                    .nth(1)
                    .map(|h| u128::from_str_radix(h, 16).unwrap().to_be_bytes());
                assert_eq!(iv.is_some(), !fmp4, "{l}");
                cur = Some((n, iv));
            } else if l == "#EXT-X-KEY:METHOD=NONE" {
                cur = None;
            } else if l.starts_with("seg-") {
                segs.push((l.to_owned(), cur));
            }
        }
        assert!(segs.len() >= 3, "{pl}");
        let init = fmp4.then(|| {
            let m = pl
                .lines()
                .find_map(|l| l.strip_prefix("#EXT-X-MAP:URI=\""))
                .unwrap()
                .trim_end_matches('"');
            let (status, _, data) = get(srv.http, &format!("/{path}/{m}"), "");
            assert_eq!(status, 200);
            for b in [&b"encv"[..], b"enca", b"sinf", b"frma", b"cbcs", b"tenc"] {
                assert!(data.windows(4).any(|w| w == b), "init lacks {b:?}");
            }
            data
        });
        for (i, (uri, key)) in segs.iter().enumerate() {
            let (n, iv) = key.unwrap_or_else(|| panic!("{uri} is not under a key: {pl}"));
            let seq: u64 = uri.split(['-', '.']).nth(1).unwrap().parse().unwrap();
            if rotate > 0 {
                assert_eq!(n, seq / 2, "{uri}: {pl}");
            }
            let (status, _, data) = get(srv.http, &format!("/{path}/{uri}"), "");
            assert_eq!(status, 200, "{uri}");
            if fmp4 {
                assert!(data.windows(4).any(|w| w == b"senc"), "{uri}");
            } else {
                // The PMT names the SAMPLE-AES stream types and descriptors.
                let pmt = &data[188..376];
                assert!(
                    pmt.windows(5).any(|w| w == [0xdb, 0xe1, 0x00, 0xf0, 6]),
                    "{pmt:x?}"
                );
                for tag in [b"zavc", b"aacd", b"apad"] {
                    assert!(pmt.windows(4).any(|w| w == tag));
                }
                // Decrypted here, every slice and AAC frame is the source's.
                let (slices, frames) =
                    decrypt_sample_aes_ts(&data, &Aes::new128(&key_of(n)), iv.unwrap());
                assert!(slices.len() > 10 && frames.len() > 20, "{uri}");
                for s in &slices {
                    assert!(src_slices.contains(s), "{uri}: a slice not in the source");
                }
                for f in &frames {
                    assert!(
                        src_audio.contains(f),
                        "{uri}: an AAC frame not in the source"
                    );
                }
            }
            if ff && i == 1 {
                // Read as plain media (no key), the frames are not the source's.
                let ext = if fmp4 { "mp4" } else { "ts" };
                let file = format!("{dir}/hlssaes-{}-{i}.{ext}", u8::from(parts));
                let mut all = init.clone().unwrap_or_default();
                all.extend_from_slice(&data);
                std::fs::write(&file, &all).unwrap();
                let got = frame_md5s(&[], &file, &[]);
                let known = got.iter().filter(|m| source.contains(m)).count();
                assert!(
                    known < got.len() / 2 || got.is_empty(),
                    "{uri} is not encrypted"
                );
                let _ = std::fs::remove_file(&file);
            }
        }
        if ff && rotate == 0 {
            let url = format!("http://{}/{path}/index.m3u8", srv.http);
            let headers = ["-headers", "X-Key-Token: secret\r\n"];
            let codecs = probe_codecs(&headers, &url);
            assert!(codecs.lines().any(|l| l.trim() == "h264"), "{codecs}");
            assert!(codecs.lines().any(|l| l.trim() == "aac"), "{codecs}");
            let err = decode(&headers, &url, &["-t", "3"]);
            assert!(err.trim().is_empty(), "{url}: {err}");
            let got = frame_md5s(&headers, &url, &["-t", "3"]);
            assert!(got.len() > 30, "{got:?}");
            for m in &got {
                assert!(source.contains(m), "a frame not in the source: {m}");
            }
        }
        publisher.join().unwrap();
        srv.engine.shutdown();
    }
}

#[test]
fn sample_aes_ts() {
    check_sample_aes(SegmentFormat::MpegTs, false, ffmpeg_present());
}

#[test]
fn sample_aes_ts_ll() {
    check_sample_aes(SegmentFormat::MpegTs, true, ffmpeg_present());
}

#[test]
fn sample_aes_fmp4() {
    check_sample_aes(SegmentFormat::Fmp4, false, ffmpeg_present());
}

#[test]
fn sample_aes_fmp4_ll() {
    check_sample_aes(SegmentFormat::Fmp4, true, ffmpeg_present());
}

/// SAMPLE-AES `cbcs` fMP4 of H.265 (slice segment headers parsed and kept clear), plain and
/// LL-HLS: `encv` with `frma` `hvc1`, `senc` in every segment, and ffmpeg plays the live
/// playlist frame for frame (every decoded frame is the source's), while a segment read as
/// plain media does not decode to the source's frames.
fn check_sample_aes_hevc(parts: bool) {
    let ff = ffmpeg_present();
    let src = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/h265_aac.flv");
    let sample = flv_sample(include_bytes!("../testdata/h265_aac.flv"));
    let path = "live/e";
    let mut cfg = HlsConfig::default();
    cfg.format = SegmentFormat::Fmp4;
    cfg.target_duration = Duration::from_secs(1);
    cfg.part_duration = parts.then(|| Duration::from_millis(250));
    cfg.play_wait = Some(Duration::from_secs(5));
    cfg.encryption = Some(HlsEncryption::new(Keys).method(EncryptionMethod::SampleAes));
    let srv = start(cfg);
    let publisher = publish(&srv.hub, path, sample, 6);
    let (status, head, _) = get(srv.http, &format!("/{path}/index.m3u8"), "");
    assert_eq!(status, 200, "{head}");
    std::thread::sleep(Duration::from_secs(4));
    let (_, _, body) = get(srv.http, &format!("/{path}/index.m3u8"), "");
    let pl = String::from_utf8(body).unwrap();
    assert!(
        pl.contains("#EXT-X-KEY:METHOD=SAMPLE-AES,URI=\"key-0.key\"\n"),
        "{pl}"
    );
    let m = pl
        .lines()
        .find_map(|l| l.strip_prefix("#EXT-X-MAP:URI=\""))
        .unwrap()
        .trim_end_matches('"');
    let (_, _, init) = get(srv.http, &format!("/{path}/{m}"), "");
    let frma = init.windows(4).position(|w| w == b"frma").expect("frma");
    assert_eq!(&init[frma + 4..frma + 8], b"hvc1");
    assert!(init.windows(4).any(|w| w == b"encv") && init.windows(4).any(|w| w == b"enca"));
    let segs: Vec<&str> = pl.lines().filter(|l| l.starts_with("seg-")).collect();
    assert!(segs.len() >= 2, "{pl}");
    let source = if ff {
        frame_md5s(&[], src, &[])
    } else {
        Vec::new()
    };
    for (i, seg) in segs.iter().enumerate() {
        let (status, _, data) = get(srv.http, &format!("/{path}/{seg}"), "");
        assert_eq!(status, 200);
        assert!(data.windows(4).any(|w| w == b"senc"), "{seg}");
        if ff && i == 1 {
            let file = format!(
                "{}/hlssaes-hevc-{}.mp4",
                env!("CARGO_TARGET_TMPDIR"),
                u8::from(parts)
            );
            let mut all = init.clone();
            all.extend_from_slice(&data);
            std::fs::write(&file, &all).unwrap();
            let got = frame_md5s(&[], &file, &[]);
            let known = got.iter().filter(|m| source.contains(m)).count();
            // The keyframe's slices start encrypted too: at most a stray identical frame.
            assert!(
                known < got.len() / 2 || got.is_empty(),
                "{seg} is not encrypted"
            );
            let _ = std::fs::remove_file(&file);
        }
    }
    if ff {
        let url = format!("http://{}/{path}/index.m3u8", srv.http);
        let headers = ["-headers", "X-Key-Token: secret\r\n"];
        let codecs = probe_codecs(&headers, &url);
        assert!(codecs.lines().any(|l| l.trim() == "hevc"), "{codecs}");
        let err = decode(&headers, &url, &["-t", "3"]);
        assert!(err.trim().is_empty(), "{url}: {err}");
        let got = frame_md5s(&headers, &url, &["-t", "3"]);
        assert!(got.len() > 30, "{got:?}");
        for m in &got {
            assert!(source.contains(m), "a frame not in the source: {m}");
        }
    }
    publisher.join().unwrap();
    srv.engine.shutdown();
}

#[test]
fn sample_aes_fmp4_hevc() {
    check_sample_aes_hevc(false);
}

#[test]
fn sample_aes_fmp4_hevc_ll() {
    check_sample_aes_hevc(true);
}
