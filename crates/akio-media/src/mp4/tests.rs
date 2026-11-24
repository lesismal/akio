use std::collections::HashMap;

use super::*;
use crate::{
    av::{Codec, Packet, SECOND, from_ticks},
    fmp4, mpegts,
};

/// The files of `testdata/mp4` (from fib's `media/mp4/testdata`, written by ffmpeg 7.1 with
/// `gen.sh`) and ffprobe's view of each.
const FILES: [(&str, &[u8], &str); 7] = [
    (
        "h264_aac",
        include_bytes!("../../testdata/mp4/h264_aac.mp4"),
        include_str!("../../testdata/mp4/h264_aac.probe"),
    ),
    (
        "h264_opus",
        include_bytes!("../../testdata/mp4/h264_opus.mp4"),
        include_str!("../../testdata/mp4/h264_opus.probe"),
    ),
    (
        "h265_aac",
        include_bytes!("../../testdata/mp4/h265_aac.mp4"),
        include_str!("../../testdata/mp4/h265_aac.probe"),
    ),
    (
        "h265_opus",
        include_bytes!("../../testdata/mp4/h265_opus.mp4"),
        include_str!("../../testdata/mp4/h265_opus.probe"),
    ),
    (
        "av1_aac",
        include_bytes!("../../testdata/mp4/av1_aac.mp4"),
        include_str!("../../testdata/mp4/av1_aac.probe"),
    ),
    (
        "av1_opus",
        include_bytes!("../../testdata/mp4/av1_opus.mp4"),
        include_str!("../../testdata/mp4/av1_opus.probe"),
    ),
    (
        "h264_aac_delay",
        include_bytes!("../../testdata/mp4/h264_aac_delay.mp4"),
        include_str!("../../testdata/mp4/h264_aac_delay.probe"),
    ),
];

type Line = HashMap<String, String>;

struct Probe {
    streams: Vec<Line>,
    raw: Vec<Vec<Line>>,
    pkt: Vec<Vec<Line>>,
}

fn probe(text: &str) -> Probe {
    let mut p = Probe {
        streams: Vec::new(),
        raw: Vec::new(),
        pkt: Vec::new(),
    };
    for line in text.lines() {
        let mut parts = line.split('|');
        let kind = parts.next().unwrap();
        let m: Line = parts
            .filter_map(|kv| kv.split_once('='))
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect();
        match kind {
            "stream" => {
                p.streams.push(m);
                p.raw.push(Vec::new());
                p.pkt.push(Vec::new());
            }
            "raw" | "pkt" => {
                let i: usize = m["stream_index"].parse().unwrap();
                if kind == "raw" {
                    p.raw[i].push(m);
                } else {
                    p.pkt[i].push(m);
                }
            }
            _ => panic!("probe line {line}"),
        }
    }
    p
}

fn num(m: &Line, k: &str) -> i64 {
    m[k].parse().unwrap_or_else(|_| panic!("{k} in {m:?}"))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn sha256(b: &[u8]) -> String {
    hex(&akio_crypto::hash::Sha256::digest(b))
}

/// The configuration as ffmpeg keeps it in `extradata`: avcC / hvcC / av1C as the box
/// payload, the AudioSpecificConfig, the OpusHead.
fn extradata(t: &Mp4Track) -> Vec<u8> {
    t.track.config.clone()
}

#[test]
fn ffprobe_fixtures() {
    for (name, file, text) in FILES {
        let p = probe(text);
        let m =
            Movie::from_bytes(file, &Limits::default()).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(m.tracks.len(), p.streams.len(), "{name}");
        assert_eq!(m.file_size, file.len() as u64);
        for (i, t) in m.tracks.iter().enumerate() {
            let st = &p.streams[i];
            let codec = match st["codec_name"].as_str() {
                "h264" => Codec::H264,
                "hevc" => Codec::H265,
                "av1" => Codec::Av1,
                "aac" => Codec::Aac,
                "opus" => Codec::Opus,
                c => panic!("{c}"),
            };
            assert_eq!(t.track.codec, codec, "{name} track {i}");
            assert_eq!(t.format, st["codec_tag_string"].as_bytes(), "{name}");
            assert_eq!(format!("1/{}", t.timescale), st["time_base"], "{name}");
            assert_eq!(i64::from(t.index.len()), num(st, "nb_frames"), "{name}");
            assert_eq!(t.language, "und", "{name}");
            if codec.is_video() {
                assert_eq!(&t.handler, b"vide");
                assert_eq!(t.name, "VideoHandler");
                assert_eq!((t.track.width, t.track.height), (64, 48), "{name}");
            } else {
                assert_eq!(&t.handler, b"soun");
                assert_eq!(
                    i64::from(t.track.sample_rate),
                    num(st, "sample_rate"),
                    "{name}"
                );
                assert_eq!(i64::from(t.track.channels), num(st, "channels"), "{name}");
            }
            let want = st["extradata_hash"].strip_prefix("SHA256:").unwrap();
            assert_eq!(sha256(&extradata(t)), want, "{name} track {i} config");
            check_samples(name, t, &p.raw[i], &p.pkt[i]);
        }
    }
}

fn check_samples(name: &str, t: &Mp4Track, raw: &[Line], pkt: &[Line]) {
    let ix = &t.index;
    assert_eq!(raw.len(), ix.len() as usize, "{name}");
    // ffmpeg decodes earlier by the most negative composition offset, so no DTS is after
    // its PTS; its PTS are the file's.
    let dts_shift = i64::from((-ix.min_cts()).max(0));
    let mut by_pos = HashMap::new();
    let mut bytes = 0u64;
    for (i, s) in ix.iter(0).enumerate() {
        assert_eq!(Some(s), ix.sample(i as u32), "{name} walked vs looked up");
        let e = &raw[i];
        let got = (
            s.offset as i64,
            i64::from(s.size),
            i64::from(s.duration),
            s.dts as i64 - dts_shift,
            s.dts as i64 + i64::from(s.cts),
            s.keyframe,
        );
        let want = (
            num(e, "pos"),
            num(e, "size"),
            num(e, "duration"),
            num(e, "dts"),
            num(e, "pts"),
            e["flags"].starts_with('K'),
        );
        assert_eq!(got, want, "{name} sample {i}");
        by_pos.insert(s.offset as i64, s);
        bytes += u64::from(s.size);
    }
    assert_eq!(bytes, ix.data_bytes(), "{name}");
    // With the edit list, every packet ffprobe reads is a sample moved by `shift`.
    assert!(!pkt.is_empty(), "{name}");
    for e in pkt {
        let s = by_pos[&num(e, "pos")];
        let pts = t.pts(&s);
        let dts = t.time(s.dts as i64 - dts_shift);
        assert_eq!(pts, from_ticks(num(e, "pts"), t.timescale), "{name} {e:?}");
        assert_eq!(dts, from_ticks(num(e, "dts"), t.timescale), "{name} {e:?}");
    }
}

#[test]
fn fixtures_layout_and_edits() {
    let m = Movie::from_bytes(FILES[0].1, &Limits::default()).unwrap();
    // h264_aac: moov at the back; B-frames start the video edit at 1024; AAC priming 1024.
    assert!(m.moov_offset > 1000);
    assert_eq!(m.major_brand, Some(*b"isom"));
    assert_eq!((m.tracks[0].shift, m.tracks[1].shift), (-1024, -1024));
    let m = Movie::from_bytes(FILES[1].1, &Limits::default()).unwrap();
    assert!(m.moov_offset < 100, "faststart");
    // h265_opus: negative composition offsets.
    let m = Movie::from_bytes(FILES[3].1, &Limits::default()).unwrap();
    assert!(m.tracks[0].index.min_cts() < 0);
    // The delayed audio: an empty edit of 0.2 s first.
    let m = Movie::from_bytes(FILES[6].1, &Limits::default()).unwrap();
    let a = &m.tracks[1];
    assert_eq!(a.edits[0].media_time, -1);
    assert!(a.shift > 0);
    assert!((a.time(0) - 200 * crate::av::MILLISECOND).abs() < 25 * crate::av::MILLISECOND);
}

#[test]
fn keyframe_lookup_by_time() {
    for (name, file, _) in FILES {
        let m = Movie::from_bytes(file, &Limits::default()).unwrap();
        let v = &m.tracks[0];
        let all: Vec<Sample> = v.index.iter(0).collect();
        for ms in (-100..1200).step_by(7) {
            let t = ms * crate::av::MILLISECOND;
            let k = v.keyframe_at(t).unwrap();
            let s = all[k as usize];
            assert!(s.keyframe, "{name}");
            // The latest keyframe presented at or before t (or the first).
            let best = all
                .iter()
                .filter(|s| s.keyframe && v.pts(s) <= t)
                .map(|s| s.index)
                .max()
                .unwrap_or_else(|| all.iter().find(|s| s.keyframe).unwrap().index);
            assert_eq!(k, best, "{name} at {ms} ms");
        }
    }
}

/// Every lookup of `ix` checked against a walk of its samples.
fn check_lookups(ix: &SampleIndex) {
    let all: Vec<Sample> = ix.iter(0).collect();
    assert_eq!(all.len(), ix.len() as usize);
    for (i, s) in all.iter().enumerate() {
        assert_eq!(ix.sample(i as u32), Some(*s));
        let from: Vec<Sample> = ix.iter(i as u32).take(3).collect();
        assert_eq!(from[..], all[i..(i + 3).min(all.len())]);
        assert_eq!(ix.is_keyframe(i as u32), s.keyframe);
        let before = all[..=i].iter().rev().find(|s| s.keyframe).map(|s| s.index);
        assert_eq!(ix.keyframe_at_or_before(i as u32), before);
        let after = all[i..].iter().find(|s| s.keyframe).map(|s| s.index);
        assert_eq!(ix.keyframe_at_or_after(i as u32), after);
        for d in [s.dts.saturating_sub(1), s.dts, s.dts + 1] {
            let want = all.iter().position(|x| x.dts >= d).unwrap_or(all.len()) as u32;
            assert_eq!(ix.first_at_or_after_dts(d), want, "dts {d}");
        }
    }
    assert_eq!(ix.sample(ix.len()), None);
    assert_eq!(ix.iter(ix.len()).next(), None);
}

#[test]
fn fixture_lookups() {
    for (_, file, _) in FILES {
        for t in Movie::from_bytes(file, &Limits::default()).unwrap().tracks {
            check_lookups(&t.index);
        }
    }
}

// ---- Files built with every form of each table. ----

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Stss {
    List,
    None,
    Empty,
    Reversed,
}

#[derive(Clone, Copy, Debug, Default)]
struct S {
    size: u32,
    duration: u32,
    cts: i32,
    sync: bool,
}

#[derive(Clone, Debug)]
struct Synth {
    timescale: u32,
    handler: [u8; 4],
    stsd: Vec<u8>,
    samples: Vec<S>,
    per_chunk: Vec<u32>,
    co64: bool,
    /// 32 for stsz, 4, 8 or 16 for stz2, 0 for a constant stsz.
    sizes: u8,
    /// 0 none, 1 version 0, 2 version 1.
    ctts: u8,
    stss: Stss,
    edits: Vec<Edit>,
    edit_v1: bool,
    v1_headers: bool,
}

fn bx(typ: &[u8; 4], parts: &[&[u8]]) -> Vec<u8> {
    let n: usize = 8 + parts.iter().map(|p| p.len()).sum::<usize>();
    let mut b = (n as u32).to_be_bytes().to_vec();
    b.extend_from_slice(typ);
    for p in parts {
        b.extend_from_slice(p);
    }
    b
}

fn full(v: u8, flags: u32) -> Vec<u8> {
    ((u32::from(v) << 24) | flags).to_be_bytes().to_vec()
}

fn be(vs: &[u32]) -> Vec<u8> {
    vs.iter().flat_map(|v| v.to_be_bytes()).collect()
}

fn sample_byte(track: usize, i: usize) -> u8 {
    (track * 37 + i) as u8
}

/// The `stsd` boxes of a file, in track order (found by their type: good enough for the
/// fixtures).
fn stsd_boxes(file: &[u8]) -> Vec<Vec<u8>> {
    let mut v = Vec::new();
    for i in 4..file.len() - 4 {
        if &file[i..i + 4] == b"stsd" {
            let n = u32::from_be_bytes(file[i - 4..i].try_into().unwrap()) as usize;
            v.push(file[i - 4..i - 4 + n].to_vec());
        }
    }
    v
}

/// The sample chunks of a track: (first sample, count) of each.
fn chunk_list(t: &Synth) -> Vec<(usize, usize)> {
    let mut v = Vec::new();
    let (mut i, mut k) = (0, 0);
    while i < t.samples.len() {
        let n = (t.per_chunk[k % t.per_chunk.len()] as usize).min(t.samples.len() - i);
        v.push((i, n));
        i += n;
        k += 1;
    }
    v
}

/// A file of `tracks`: `ftyp`, then `moov` and `mdat` in the order `moov_first` says (the
/// `mdat` with a 64-bit size if `large`), chunks of the tracks interleaved. Returns the file
/// and every sample's offset.
fn build(tracks: &[Synth], moov_first: bool, large: bool) -> (Vec<u8>, Vec<Vec<u64>>) {
    let ftyp = bx(b"ftyp", &[b"isom", &be(&[512]), b"isomiso2mp41"]);
    let chunks: Vec<_> = tracks.iter().map(chunk_list).collect();
    // The mdat payload: chunk k of every track, in turn.
    let mut payload = Vec::new();
    let mut at: Vec<Vec<usize>> = tracks.iter().map(|_| Vec::new()).collect();
    let rounds = chunks.iter().map(Vec::len).max().unwrap_or(0);
    for k in 0..rounds {
        for (ti, t) in tracks.iter().enumerate() {
            if let Some(&(first, n)) = chunks[ti].get(k) {
                at[ti].push(payload.len());
                for (i, sample) in t.samples.iter().enumerate().skip(first).take(n) {
                    payload.extend(std::iter::repeat_n(
                        sample_byte(ti, i),
                        sample.size as usize,
                    ));
                }
            }
        }
    }
    let mdat_hdr = if large { 16 } else { 8 };
    let mdat = |base: u64| -> Vec<u8> {
        let _ = base;
        let mut m = Vec::new();
        if large {
            m.extend_from_slice(&1u32.to_be_bytes());
            m.extend_from_slice(b"mdat");
            m.extend_from_slice(&((payload.len() + 16) as u64).to_be_bytes());
        } else {
            m.extend_from_slice(&((payload.len() + 8) as u32).to_be_bytes());
            m.extend_from_slice(b"mdat");
        }
        m.extend_from_slice(&payload);
        m
    };
    let moov_for = |data_at: u64| -> Vec<u8> {
        let mvhd = bx(b"mvhd", &[&full(0, 0), &be(&[0, 0, 1000, 0]), &[0u8; 80]]);
        let mut traks = Vec::new();
        for (ti, t) in tracks.iter().enumerate() {
            let offs: Vec<u64> = at[ti].iter().map(|&a| data_at + a as u64).collect();
            traks.push(trak(ti, t, &chunks[ti], &offs));
        }
        let mut parts: Vec<&[u8]> = vec![&mvhd];
        for t in &traks {
            parts.push(t);
        }
        bx(b"moov", &parts)
    };
    let file = if moov_first {
        let size = moov_for(0).len();
        let data_at = (ftyp.len() + size + mdat_hdr) as u64;
        [ftyp.clone(), moov_for(data_at), mdat(data_at)].concat()
    } else {
        let data_at = (ftyp.len() + mdat_hdr) as u64;
        [ftyp.clone(), mdat(data_at), moov_for(data_at)].concat()
    };
    let data_at = if moov_first {
        (ftyp.len() + moov_for(0).len() + mdat_hdr) as u64
    } else {
        (ftyp.len() + mdat_hdr) as u64
    };
    let offsets = tracks
        .iter()
        .enumerate()
        .map(|(ti, t)| {
            let mut v = Vec::new();
            for (k, &(first, n)) in chunks[ti].iter().enumerate() {
                let mut o = data_at + at[ti][k] as u64;
                for sample in t.samples.iter().skip(first).take(n) {
                    v.push(o);
                    o += u64::from(sample.size);
                }
            }
            v
        })
        .collect();
    (file, offsets)
}

fn trak(ti: usize, t: &Synth, chunks: &[(usize, usize)], offs: &[u64]) -> Vec<u8> {
    let id = ti as u32 + 1;
    let tkhd = if t.v1_headers {
        bx(
            b"tkhd",
            &[
                &full(1, 3),
                &[0u8; 16],
                &be(&[id, 0]),
                &[0u8; 8],
                &[0u8; 60],
            ],
        )
    } else {
        bx(b"tkhd", &[&full(0, 3), &be(&[0, 0, id, 0, 0]), &[0u8; 60]])
    };
    let lang = (5u16 << 10) | (14 << 5) | 7; // "eng"
    let mdhd = if t.v1_headers {
        bx(
            b"mdhd",
            &[
                &full(1, 0),
                &[0u8; 16],
                &be(&[t.timescale]),
                &u64::MAX.to_be_bytes(),
                &lang.to_be_bytes(),
                &[0, 0],
            ],
        )
    } else {
        bx(
            b"mdhd",
            &[
                &full(0, 0),
                &be(&[0, 0, t.timescale, 0]),
                &lang.to_be_bytes(),
                &[0, 0],
            ],
        )
    };
    let hdlr = bx(
        b"hdlr",
        &[&full(0, 0), &[0u8; 4], &t.handler, &[0u8; 12], b"Synth\0"],
    );
    let n = t.samples.len() as u32;
    // stts runs.
    let mut runs: Vec<(u32, u32)> = Vec::new();
    for s in &t.samples {
        match runs.last_mut() {
            Some(r) if r.1 == s.duration => r.0 += 1,
            _ => runs.push((1, s.duration)),
        }
    }
    let mut stts = vec![runs.len() as u32];
    for r in &runs {
        stts.extend([r.0, r.1]);
    }
    let stts = bx(b"stts", &[&full(0, 0), &be(&stts)]);
    let ctts = if t.ctts > 0 {
        let mut runs: Vec<(u32, i32)> = Vec::new();
        for s in &t.samples {
            match runs.last_mut() {
                Some(r) if r.1 == s.cts => r.0 += 1,
                _ => runs.push((1, s.cts)),
            }
        }
        let mut v = vec![runs.len() as u32];
        for r in &runs {
            v.extend([r.0, r.1 as u32]);
        }
        bx(b"ctts", &[&full(t.ctts - 1, 0), &be(&v)])
    } else {
        Vec::new()
    };
    let mut sync: Vec<u32> = (0..n)
        .filter(|&i| t.samples[i as usize].sync)
        .map(|i| i + 1)
        .collect();
    let stss = match t.stss {
        Stss::None => Vec::new(),
        Stss::Empty => bx(b"stss", &[&full(0, 0), &be(&[0])]),
        Stss::List | Stss::Reversed => {
            if t.stss == Stss::Reversed {
                sync.reverse();
            }
            let mut v = vec![sync.len() as u32];
            v.extend(&sync);
            bx(b"stss", &[&full(0, 0), &be(&v)])
        }
    };
    // stsc: an entry wherever the count changes.
    let mut sc: Vec<u32> = Vec::new();
    let mut last = u32::MAX;
    for (k, &(_, c)) in chunks.iter().enumerate() {
        if c as u32 != last {
            sc.extend([k as u32 + 1, c as u32, 1]);
            last = c as u32;
        }
    }
    let stsc = bx(
        b"stsc",
        &[&full(0, 0), &be(&[(sc.len() / 3) as u32]), &be(&sc)],
    );
    let co = if t.co64 {
        let mut v = be(&[offs.len() as u32]);
        for o in offs {
            v.extend_from_slice(&o.to_be_bytes());
        }
        bx(b"co64", &[&full(0, 0), &v])
    } else {
        let mut v = vec![offs.len() as u32];
        v.extend(offs.iter().map(|&o| o as u32));
        bx(b"stco", &[&full(0, 0), &be(&v)])
    };
    let sizes: Vec<u32> = t.samples.iter().map(|s| s.size).collect();
    let sz = match t.sizes {
        0 => bx(
            b"stsz",
            &[&full(0, 0), &be(&[sizes.first().copied().unwrap_or(1), n])],
        ),
        32 => {
            let mut v = vec![0, n];
            v.extend(&sizes);
            bx(b"stsz", &[&full(0, 0), &be(&v)])
        }
        f => {
            let mut v = vec![0u8, 0, 0, f];
            v.extend(be(&[n]));
            match f {
                4 => {
                    for c in sizes.chunks(2) {
                        v.push(((c[0] as u8) << 4) | c.get(1).map_or(0, |&x| x as u8));
                    }
                }
                8 => v.extend(sizes.iter().map(|&s| s as u8)),
                _ => v.extend(sizes.iter().flat_map(|&s| (s as u16).to_be_bytes())),
            }
            bx(b"stz2", &[&full(0, 0), &v])
        }
    };
    let stbl = bx(b"stbl", &[&t.stsd, &stts, &ctts, &stss, &stsc, &sz, &co]);
    let minf = bx(b"minf", &[&stbl]);
    let mdia = bx(b"mdia", &[&mdhd, &hdlr, &minf]);
    let edts = if t.edits.is_empty() {
        Vec::new()
    } else {
        let v = u8::from(t.edit_v1);
        let mut e = full(v, 0);
        e.extend(be(&[t.edits.len() as u32]));
        for ed in &t.edits {
            if t.edit_v1 {
                e.extend(ed.duration.to_be_bytes());
                e.extend(ed.media_time.to_be_bytes());
            } else {
                e.extend((ed.duration as u32).to_be_bytes());
                e.extend((ed.media_time as i32).to_be_bytes());
            }
            e.extend(ed.rate.to_be_bytes());
        }
        bx(b"edts", &[&bx(b"elst", &[&e])])
    };
    bx(b"trak", &[&tkhd, &edts, &mdia])
}

fn fixture_stsd() -> (Vec<u8>, Vec<u8>) {
    let s = stsd_boxes(FILES[0].1);
    (s[0].clone(), s[1].clone())
}

/// A video track of `n` samples: GOPs of 5, B-frames (composition offsets), sizes from
/// `size`.
fn video(n: usize, size: impl Fn(usize) -> u32) -> Synth {
    let (v, _) = fixture_stsd();
    Synth {
        timescale: 12800,
        handler: *b"vide",
        stsd: v,
        samples: (0..n)
            .map(|i| S {
                size: size(i),
                duration: 512,
                cts: if i % 5 == 0 {
                    1024
                } else {
                    [0, 1536, 0, 512][i % 4]
                },
                sync: i % 5 == 0,
            })
            .collect(),
        per_chunk: vec![3, 1, 4],
        co64: false,
        sizes: 32,
        ctts: 1,
        stss: Stss::List,
        edits: Vec::new(),
        edit_v1: false,
        v1_headers: false,
    }
}

fn audio(n: usize) -> Synth {
    let (_, a) = fixture_stsd();
    Synth {
        timescale: 48000,
        handler: *b"soun",
        stsd: a,
        samples: (0..n)
            .map(|i| S {
                size: 20 + (i % 7) as u32,
                duration: 1024,
                cts: 0,
                sync: true,
            })
            .collect(),
        per_chunk: vec![2],
        co64: false,
        sizes: 32,
        ctts: 0,
        stss: Stss::None,
        edits: Vec::new(),
        edit_v1: false,
        v1_headers: false,
    }
}

/// Reads `file` and checks every sample of every track against what was built.
fn check_built(tracks: &[Synth], file: &[u8], offsets: &[Vec<u64>]) -> Movie {
    let m = Movie::from_bytes(file, &Limits::default()).unwrap();
    assert_eq!(m.tracks.len(), tracks.len());
    for (ti, (t, want)) in m.tracks.iter().zip(tracks).enumerate() {
        assert_eq!(t.id, ti as u32 + 1);
        assert_eq!(t.language, "eng");
        assert_eq!(t.name, "Synth");
        assert_eq!(t.timescale, want.timescale);
        assert_eq!(t.edits, want.edits);
        let mut dts = 0u64;
        for (i, s) in t.index.iter(0).enumerate() {
            let w = want.samples[i];
            let sync = match want.stss {
                Stss::None => true,
                Stss::Empty => false,
                _ => w.sync,
            };
            let cts = if want.ctts > 0 { w.cts } else { 0 };
            assert_eq!(
                (s.offset, s.size, s.dts, s.cts, s.duration, s.keyframe),
                (offsets[ti][i], w.size, dts, cts, w.duration, sync),
                "track {ti} sample {i} of {want:?}"
            );
            let b = &file[s.offset as usize..][..s.size as usize];
            assert!(b.iter().all(|&x| x == sample_byte(ti, i)));
            dts += u64::from(w.duration);
        }
        assert_eq!(t.index.end_dts(), dts);
        check_lookups(&t.index);
    }
    m
}

#[test]
fn every_table_form() {
    for sizes in [32u8, 16, 8, 4, 0] {
        for ctts in [0u8, 1, 2] {
            for stss in [Stss::List, Stss::None, Stss::Empty, Stss::Reversed] {
                for (co64, moov_first, large, v1) in
                    [(false, true, false, false), (true, false, true, true)]
                {
                    let max = match sizes {
                        4 => 15,
                        8 => 255,
                        16 => 60_000,
                        _ => 70_000,
                    };
                    let mut v = video(23, |i| {
                        if sizes == 0 {
                            9
                        } else {
                            (i as u32 * 7919 + 3) % max + 1
                        }
                    });
                    (v.sizes, v.ctts, v.stss, v.co64, v.v1_headers) = (sizes, ctts, stss, co64, v1);
                    if ctts == 2 {
                        for s in &mut v.samples {
                            s.cts -= 1024; // negative offsets
                        }
                    }
                    let mut a = audio(31);
                    a.co64 = co64;
                    let tracks = [v, a];
                    let (file, offs) = build(&tracks, moov_first, large);
                    let m = check_built(&tracks, &file, &offs);
                    assert_eq!(m.moov_offset < 100, moov_first);
                }
            }
        }
    }
}

#[test]
fn empty_and_uneven_chunks() {
    // Chunks of 0, 1 and 5 samples: empty chunks are skipped.
    let mut v = video(17, |i| 100 + i as u32);
    v.per_chunk = vec![1, 5, 2];
    let (file, offs) = build(&[v.clone()], true, false);
    check_built(&[v], &file, &offs);
    // A track without samples.
    let mut e = audio(0);
    e.samples.clear();
    let (file, _) = build(&[e], false, false);
    let m = Movie::from_bytes(&file, &Limits::default()).unwrap();
    assert!(m.tracks[0].index.is_empty());
    assert_eq!(m.tracks[0].index.sample(0), None);
    assert!(Plan::new(&m, SECOND).unwrap().is_empty());
}

#[test]
fn edit_lists() {
    for (edits, v1, shift) in [
        (vec![], false, 0),
        (
            vec![Edit {
                duration: 1000,
                media_time: 1024,
                rate: 1 << 16,
            }],
            false,
            -1024,
        ),
        (
            vec![
                Edit {
                    duration: 200,
                    media_time: -1,
                    rate: 1 << 16,
                },
                Edit {
                    duration: 1000,
                    media_time: 1024,
                    rate: 1 << 16,
                },
            ],
            true,
            2560 - 1024, // 0.2 s at 12800 Hz
        ),
        (
            vec![
                Edit {
                    duration: 100,
                    media_time: -1,
                    rate: 1 << 16,
                },
                Edit {
                    duration: 100,
                    media_time: -1,
                    rate: 1 << 16,
                },
                Edit {
                    duration: 500,
                    media_time: 0,
                    rate: 1 << 16,
                },
                Edit {
                    duration: 500,
                    media_time: 5000,
                    rate: 1 << 16,
                },
            ],
            false,
            2560,
        ),
    ] {
        let mut v = video(10, |_| 10);
        (v.edits, v.edit_v1) = (edits.clone(), v1);
        let (file, offs) = build(&[v.clone()], true, false);
        let m = check_built(&[v], &file, &offs);
        assert_eq!(m.tracks[0].shift, shift, "{edits:?}");
        assert_eq!(m.tracks[0].time(0), from_ticks(shift, 12800));
        assert_eq!(m.tracks[0].ticks(m.tracks[0].time(77)), 77);
    }
    assert_eq!(
        parse::shift(
            &[Edit {
                duration: u64::MAX,
                media_time: -1,
                rate: 0
            }],
            1,
            u32::MAX
        ),
        i64::MAX / 4
    );
}

// ---- Malformed input and limits. ----

#[test]
fn truncated_files_never_panic() {
    for (name, file, _) in FILES {
        for n in 0..file.len() {
            let _ = Movie::from_bytes(&file[..n], &Limits::default());
        }
        // Cut inside the moov at the back, or inside the mdat after a front moov: the first
        // is lost, the second reads (its chunks point past the end, which is refused).
        let m = Movie::from_bytes(file, &Limits::default()).unwrap();
        let cut = &file[..file.len() - 1];
        let r = Movie::from_bytes(cut, &Limits::default());
        if m.moov_offset + m.moov_size == file.len() as u64 {
            assert_eq!(r.unwrap_err(), Mp4Error::NoMoov, "{name}");
        } else {
            assert!(
                matches!(r, Err(Mp4Error::NoMoov | Mp4Error::Invalid(_))),
                "{name}: {r:?}"
            );
        }
    }
}

#[test]
fn corrupt_files_never_panic() {
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    let mut rnd = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for (_, file, _) in FILES {
        let m = Movie::from_bytes(file, &Limits::default()).unwrap();
        let (a, b) = (
            m.moov_offset as usize,
            (m.moov_offset + m.moov_size) as usize,
        );
        for _ in 0..1500 {
            let mut f = file.to_vec();
            for _ in 0..=(rnd() % 4) {
                let at = a + (rnd() as usize) % (b - a);
                f[at] = match rnd() % 4 {
                    0 => 0,
                    1 => 0xff,
                    2 => f[at] ^ (1 << (rnd() % 8)),
                    _ => rnd() as u8,
                };
            }
            if let Ok(m) = Movie::from_bytes(&f, &Limits::default()) {
                crate::fuzzing::mp4::exercise(&m, &f);
            }
        }
    }
}

#[test]
fn malformed_tables_are_refused() {
    let base = video(12, |i| 50 + i as u32);
    let read = |t: &Synth| {
        let (f, _) = build(std::slice::from_ref(t), true, false);
        Movie::from_bytes(&f, &Limits::default()).map(|_| ())
    };
    assert_eq!(read(&base), Ok(()));
    // stts short of the sample count.
    let mut t = base.clone();
    t.samples[11].duration = 7; // a run of its own...
    let (mut f, _) = build(&[t], true, false);
    // ...whose count is zeroed.
    let stts = f.windows(4).position(|w| w == b"stts").unwrap();
    let n = u32::from_be_bytes(f[stts + 8..stts + 12].try_into().unwrap()) as usize;
    let last = stts + 12 + (n - 1) * 8;
    f[last..last + 4].copy_from_slice(&0u32.to_be_bytes());
    assert_eq!(
        Movie::from_bytes(&f, &Limits::default()).unwrap_err(),
        Mp4Error::Invalid("stts (fewer samples than stsz)")
    );
    // A chunk past the end of the file.
    let (mut f, _) = build(std::slice::from_ref(&base), false, false);
    let stco = f.windows(4).position(|w| w == b"stco").unwrap();
    f[stco + 12..stco + 16].copy_from_slice(&0xffff_0000u32.to_be_bytes());
    assert_eq!(
        Movie::from_bytes(&f, &Limits::default()).unwrap_err(),
        Mp4Error::Invalid("chunk (sample data outside the file)")
    );
    // stsc not covering every sample.
    let (mut f, _) = build(std::slice::from_ref(&base), false, false);
    let stsc = f.windows(4).position(|w| w == b"stsc").unwrap();
    let n = u32::from_be_bytes(f[stsc + 8..stsc + 12].try_into().unwrap()) as usize;
    for k in 0..n {
        let at = stsc + 12 + k * 12 + 4;
        f[at..at + 4].copy_from_slice(&1u32.to_be_bytes());
    }
    assert_eq!(
        Movie::from_bytes(&f, &Limits::default()).unwrap_err(),
        Mp4Error::Invalid("stsc (samples outside every chunk)")
    );
    // An stsz claiming more entries than its box holds.
    let (mut f, _) = build(std::slice::from_ref(&base), false, false);
    let stsz = f.windows(4).position(|w| w == b"stsz").unwrap();
    f[stsz + 12..stsz + 16].copy_from_slice(&1000u32.to_be_bytes());
    assert_eq!(
        Movie::from_bytes(&f, &Limits::default()).unwrap_err(),
        Mp4Error::Truncated
    );
    // A fragmented file.
    let mut t = bx(b"ftyp", &[b"iso6", &be(&[0])]);
    t.extend(bx(b"moof", &[]));
    assert_eq!(
        Movie::from_bytes(&t, &Limits::default()).unwrap_err(),
        Mp4Error::Fragmented
    );
    let (mut f, _) = build(std::slice::from_ref(&base), true, false);
    let mvhd = f.windows(4).position(|w| w == b"mvhd").unwrap();
    f[mvhd..mvhd + 4].copy_from_slice(b"mvex");
    assert_eq!(
        Movie::from_bytes(&f, &Limits::default()).unwrap_err(),
        Mp4Error::Fragmented
    );
    // No moov at all.
    let t = bx(b"ftyp", &[b"isom", &be(&[0])]);
    assert_eq!(
        Movie::from_bytes(&t, &Limits::default()).unwrap_err(),
        Mp4Error::NoMoov
    );
    assert_eq!(
        Movie::from_bytes(&[], &Limits::default()).unwrap_err(),
        Mp4Error::NoMoov
    );
}

#[test]
fn limits_at_and_over() {
    let v = video(40, |_| 10);
    let mut a = audio(40);
    a.edits = vec![
        Edit {
            duration: 1,
            media_time: 0,
            rate: 1 << 16
        };
        3
    ];
    let (file, _) = build(&[v, a], true, false);
    let ok = |l: Limits| Movie::from_bytes(&file, &l);
    let d = Limits::default();
    assert!(
        ok(Limits {
            max_samples: 40,
            ..d
        })
        .is_ok()
    );
    assert_eq!(
        ok(Limits {
            max_samples: 39,
            ..d
        })
        .unwrap_err(),
        Mp4Error::Limit("samples")
    );
    assert!(ok(Limits { max_tracks: 2, ..d }).is_ok());
    assert_eq!(
        ok(Limits { max_tracks: 1, ..d }).unwrap_err(),
        Mp4Error::Limit("tracks")
    );
    assert!(ok(Limits { max_edits: 3, ..d }).is_ok());
    assert_eq!(
        ok(Limits { max_edits: 2, ..d }).unwrap_err(),
        Mp4Error::Limit("edits")
    );
    let m = ok(d).unwrap();
    assert!(
        ok(Limits {
            max_moov_bytes: m.moov_size,
            ..d
        })
        .is_ok()
    );
    assert_eq!(
        ok(Limits {
            max_moov_bytes: m.moov_size - 1,
            ..d
        })
        .unwrap_err(),
        Mp4Error::Limit("moov bytes")
    );
    // Boxes: find the count that just passes.
    let pass = (1..200)
        .find(|&n| ok(Limits { max_boxes: n, ..d }).is_ok())
        .unwrap();
    assert_eq!(
        ok(Limits {
            max_boxes: pass - 1,
            ..d
        })
        .unwrap_err(),
        Mp4Error::Limit("boxes")
    );
    // Segments: 40 frames of 25 fps, a keyframe every 5 (0.2 s).
    let plan = Plan::with_limit(&m, SECOND / 5, 8).unwrap();
    assert_eq!(plan.len(), 8);
    assert_eq!(
        Plan::with_limit(&m, SECOND / 5, 7).unwrap_err(),
        Mp4Error::Limit("segments")
    );
    assert_eq!(
        Plan::new(&m, 0).unwrap_err(),
        Mp4Error::Invalid("segment target duration")
    );
}

#[test]
fn huge_counts_allocate_nothing() {
    // A constant-size stsz of 2^24 samples with one stts run and one chunk: no table a
    // sample is built.
    let mut v = video(1, |_| 1);
    v.sizes = 0;
    v.stss = Stss::None;
    v.ctts = 0;
    let (mut f, _) = build(&[v], true, false);
    let n = 1u32 << 24;
    let stsz = f.windows(4).position(|w| w == b"stsz").unwrap();
    f[stsz + 12..stsz + 16].copy_from_slice(&n.to_be_bytes());
    let stts = f.windows(4).position(|w| w == b"stts").unwrap();
    f[stts + 12..stts + 16].copy_from_slice(&n.to_be_bytes());
    let stsc = f.windows(4).position(|w| w == b"stsc").unwrap();
    f[stsc + 16..stsc + 20].copy_from_slice(&n.to_be_bytes());
    // The chunk's 2^24 bytes are not in the file.
    assert_eq!(
        Movie::from_bytes(&f, &Limits::default()).unwrap_err(),
        Mp4Error::Invalid("chunk (sample data outside the file)")
    );
    f.resize(f.len() + n as usize, 0);
    let m = Movie::from_bytes(&f, &Limits::default()).unwrap();
    assert_eq!(m.tracks[0].index.len(), n);
    assert!(m.index_bytes() < 256, "{}", m.index_bytes());
    assert_eq!(
        m.tracks[0].index.sample(n - 1).unwrap().offset,
        m.tracks[0].index.sample(0).unwrap().offset + u64::from(n) - 1
    );
}

#[test]
fn locator_reads_headers_only() {
    for (name, file, _) in FILES {
        let l = Limits::default();
        let mut loc = Locator::new(file.len() as u64, &l);
        let mut reads = 0;
        let at = loop {
            let (off, len) = loc.next_read();
            assert!(len <= HEADER_BYTES);
            reads += 1;
            if let Some(at) = loc.feed(&file[off as usize..off as usize + len]).unwrap() {
                break at;
            }
        };
        assert!(reads <= 4, "{name}: {reads} reads");
        let m = Movie::from_bytes(file, &l).unwrap();
        assert_eq!((at.offset, at.size), (m.moov_offset, m.moov_size));
        // Fewer bytes than asked for.
        let mut loc = Locator::new(file.len() as u64, &l);
        assert_eq!(loc.feed(&file[..4]).unwrap_err(), Mp4Error::Truncated);
    }
    // A size-0 box runs to the end of the file; 64-bit sizes are read.
    let mut f = bx(b"ftyp", &[b"mp42", &be(&[0])]);
    f.extend(1u32.to_be_bytes());
    f.extend(b"free");
    f.extend(24u64.to_be_bytes());
    f.extend([0u8; 8]);
    f.extend(0u32.to_be_bytes());
    f.extend(b"moov");
    let mut loc = Locator::new(f.len() as u64, &Limits::default());
    let at = loc.feed(&f).unwrap().unwrap();
    assert_eq!(
        (at.offset, at.size, at.major_brand),
        (40, 8, Some(*b"mp42"))
    );
    // Box limit.
    let f: Vec<u8> = (0..10).flat_map(|_| bx(b"free", &[])).collect();
    let mut loc = Locator::new(
        f.len() as u64,
        &Limits {
            max_boxes: 9,
            ..Limits::default()
        },
    );
    assert_eq!(loc.feed(&f).unwrap_err(), Mp4Error::Limit("boxes"));
}

// ---- Segments. ----

/// The packets of every segment of `plan`, read from the whole file.
fn all_packets(m: &Movie, plan: &Plan, file: &[u8]) -> Vec<Vec<Packet>> {
    (0..plan.len())
        .map(|i| {
            let seg = plan.segment(m, i);
            let ranges = seg.byte_ranges(m, 0);
            let parts: Vec<(u64, &[u8])> = ranges
                .iter()
                .map(|r| (r.start, &file[r.start as usize..r.end as usize]))
                .collect();
            seg.packets(m, &parts).unwrap()
        })
        .collect()
}

#[test]
fn plan_cuts_at_keyframes() {
    for (name, file, _) in FILES {
        let m = Movie::from_bytes(file, &Limits::default()).unwrap();
        for target in [
            SECOND / 5,
            300 * crate::av::MILLISECOND,
            SECOND,
            10 * SECOND,
        ] {
            let plan = Plan::new(&m, target).unwrap();
            assert_eq!(plan.reference_track(), Some(0));
            assert!(plan.delay() >= 0);
            let segs = all_packets(&m, &plan, file);
            // Every sample is in exactly one segment, once.
            for (j, t) in m.tracks.iter().enumerate() {
                let mut next = 0;
                for i in 0..plan.len() {
                    let r = plan.segment(&m, i).samples[j].clone();
                    assert_eq!(r.start, next, "{name} track {j} segment {i}");
                    next = r.end;
                }
                assert_eq!(next, t.index.len(), "{name}");
                let n: usize = segs.iter().flatten().filter(|p| p.track == j).count();
                assert_eq!(n, t.index.len() as usize);
            }
            for (i, pkts) in segs.iter().enumerate() {
                let seg = plan.segment(&m, i);
                // Video starts at a keyframe; every segment but the last is long enough.
                let first = pkts.iter().find(|p| p.track == 0).unwrap();
                assert!(first.keyframe, "{name} segment {i}");
                if i + 1 < plan.len() {
                    assert!(plan.duration(i) >= target, "{name} {i}");
                    assert_eq!(seg.end, plan.start(i + 1));
                }
                assert_eq!(seg.start, plan.start(i));
                if i > 0 {
                    assert_eq!(first.pts, seg.start, "{name} {i}");
                }
                // Decode order, no negative time, audio inside the segment.
                assert!(pkts.windows(2).all(|w| w[0].dts <= w[1].dts));
                assert!(pkts.iter().all(|p| p.dts >= 0 && p.pts >= 0), "{name}");
                for p in pkts.iter().filter(|p| p.track == 1) {
                    assert!(p.dts >= seg.start || i == 0, "{name} {i}");
                    assert!(p.dts < seg.end || i + 1 == plan.len(), "{name} {i}");
                }
                assert_eq!(plan.segment_at(seg.start), Some(i));
            }
            let pl = plan.vod_playlist(None, |i| format!("s{i}.ts"));
            assert!(pl.ends_with("#EXT-X-ENDLIST\n"));
            assert_eq!(pl.matches("#EXTINF:").count(), plan.len());
            assert!(pl.contains(&format!(
                "#EXT-X-TARGETDURATION:{}\n",
                plan.target_duration()
            )));
        }
        // A 1 s file at 1 s: one segment holding it all.
        let plan = Plan::new(&m, 10 * SECOND).unwrap();
        assert_eq!(plan.len(), 1);
        assert_eq!(plan.segment(&m, 1).sample_count(), 0);
    }
}

#[test]
fn segment_bytes_and_missing_data() {
    let (name, file, _) = FILES[0];
    let m = Movie::from_bytes(file, &Limits::default()).unwrap();
    let plan = Plan::new(&m, SECOND / 5).unwrap();
    let seg = plan.segment(&m, 1);
    let tight = seg.byte_ranges(&m, 0);
    let loose = seg.byte_ranges(&m, 1 << 20);
    assert_eq!(loose.len(), 1, "{name}");
    assert!(tight.len() >= loose.len());
    assert!(tight.windows(2).all(|w| w[0].end < w[1].start));
    let total: u64 = tight.iter().map(|r| r.end - r.start).sum();
    let samples: u64 = m
        .tracks
        .iter()
        .zip(&seg.samples)
        .flat_map(|(t, r)| t.index.range(r.start, r.end))
        .map(|s| u64::from(s.size))
        .sum();
    assert_eq!(total, samples);
    // Without the last range, a sample is missing.
    let parts: Vec<(u64, &[u8])> = tight[..tight.len() - 1]
        .iter()
        .map(|r| (r.start, &file[r.start as usize..r.end as usize]))
        .collect();
    assert_eq!(seg.packets(&m, &parts).unwrap_err(), Mp4Error::MissingData);
    // Ranges given in any order, or the whole file.
    let mut parts: Vec<(u64, &[u8])> = tight
        .iter()
        .map(|r| (r.start, &file[r.start as usize..r.end as usize]))
        .collect();
    parts.reverse();
    assert_eq!(
        seg.packets(&m, &parts).unwrap(),
        seg.packets(&m, &[(0, file)]).unwrap()
    );
}

#[test]
fn segments_mux_to_fmp4_and_back() {
    for (name, file, _) in FILES {
        let m = Movie::from_bytes(file, &Limits::default()).unwrap();
        let plan = Plan::new(&m, SECOND / 5).unwrap();
        let tracks = m.av_tracks();
        let mut mux = fmp4::Muxer::new(&tracks);
        let init = mux.init_segment().to_vec();
        let segs = all_packets(&m, &plan, file);
        for i in (0..plan.len()).rev() {
            let seg = plan.segment(&m, i);
            let mut out = init.clone();
            seg.write_fmp4(&m, &[(0, file)], &mut mux, &mut out)
                .unwrap();
            let (t, pkts) = fmp4::demux_all(&out).unwrap();
            assert_eq!(t.unwrap().len(), tracks.len(), "{name}");
            // The fragment's sequence number is the segment's.
            let mfhd = out.windows(4).position(|w| w == b"mfhd").unwrap();
            assert_eq!(&out[mfhd + 8..mfhd + 12], &(i as u32 + 1).to_be_bytes());
            assert_eq!(pkts.len(), segs[i].len(), "{name} {i}");
            for j in 0..tracks.len() {
                let a: Vec<_> = pkts.iter().filter(|p| p.track == j).collect();
                let b: Vec<_> = segs[i].iter().filter(|p| p.track == j).collect();
                for (a, b) in a.iter().zip(&b) {
                    assert_eq!(a.data, b.data, "{name}");
                    assert_eq!(a.keyframe, b.keyframe, "{name}");
                    // The muxer's clock is 90 kHz for video, the rate for audio.
                    assert!(
                        (a.dts - b.dts).abs() <= 20_000,
                        "{name} {} {}",
                        a.dts,
                        b.dts
                    );
                    assert!((a.pts - b.pts).abs() <= 20_000, "{name}");
                }
            }
        }
    }
}

#[test]
fn segments_mux_to_ts_and_back() {
    for (name, file, _) in FILES {
        let m = Movie::from_bytes(file, &Limits::default()).unwrap();
        let plan = Plan::new(&m, 300 * crate::av::MILLISECOND).unwrap();
        let tracks = m.av_tracks();
        let segs = all_packets(&m, &plan, file);
        for (i, want) in segs.iter().enumerate() {
            let mut out = Vec::new();
            let mut mux = mpegts::Muxer::new(&tracks);
            plan.segment(&m, i)
                .write_ts(&m, &[(0, file)], &mut mux, &mut out)
                .unwrap();
            let mut d = mpegts::demux::Demuxer::new();
            let mut got = Vec::new();
            let mut emit = |e| {
                if let mpegts::demux::Event::Packet(p) = e {
                    got.push(p);
                }
            };
            d.feed(&out, &mut emit).unwrap();
            d.flush(&mut emit);
            let carried: Vec<_> = want.iter().filter(|p| mux.carries(p.track)).collect();
            let video = |v: &[&Packet]| v.iter().filter(|p| p.track == 0).count();
            assert_eq!(
                video(&got.iter().collect::<Vec<_>>()),
                video(&carried),
                "{name} segment {i}"
            );
            let first = got.iter().find(|p| p.track == 0);
            if let Some(f) = first {
                assert!(f.keyframe, "{name} {i}");
            }
        }
    }
}

#[test]
fn short_nal_lengths_are_widened() {
    // An avcC with 2-byte NAL lengths and samples to match.
    let sps = [0x67, 0x64, 0x00, 0x1f, 0xac, 0xd9];
    let mut c = crate::codec::h264::Config::from_sets(&sps, &[0x68, 0xee]);
    c.length_size = 2;
    let avcc = c.encode();
    assert_eq!(avcc[4] & 3, 1);
    let mut entry = vec![0u8; 78];
    entry[6..8].copy_from_slice(&1u16.to_be_bytes());
    entry[24..26].copy_from_slice(&64u16.to_be_bytes());
    entry[26..28].copy_from_slice(&48u16.to_be_bytes());
    let avc1 = bx(b"avc1", &[&entry, &bx(b"avcC", &[&avcc])]);
    let stsd = bx(b"stsd", &[&full(0, 0), &be(&[1]), &avc1]);
    let mut v = video(6, |_| 7);
    v.stsd = stsd;
    v.sizes = 0;
    let (mut file, offs) = build(&[v], true, false);
    // Each sample: two NAL units of 1 and 2 bytes behind 2-byte lengths.
    for (i, &o) in offs[0].iter().enumerate() {
        let o = o as usize;
        let t = if i % 5 == 0 { 0x65 } else { 0x41 };
        file[o..o + 7].copy_from_slice(&[0, 1, t, 0, 2, 0xaa, 0xbb]);
    }
    let m = Movie::from_bytes(&file, &Limits::default()).unwrap();
    assert_eq!(m.av_tracks()[0].config[4] & 3, 3);
    assert_eq!(
        m.tracks[0].track.config[4] & 3,
        1,
        "the track keeps the record as stored"
    );
    let plan = Plan::new(&m, SECOND).unwrap();
    let p = plan.segment(&m, 0).packets(&m, &[(0, &file)]).unwrap();
    assert_eq!(p[0].data, [0, 0, 0, 1, 0x65, 0, 0, 0, 2, 0xaa, 0xbb]);
    // A length running past the sample.
    let o = offs[0][1] as usize;
    file[o + 3..o + 5].copy_from_slice(&[0, 9]);
    let m = Movie::from_bytes(&file, &Limits::default()).unwrap();
    assert_eq!(
        plan.segment(&m, 0).packets(&m, &[(0, &file)]).unwrap_err(),
        Mp4Error::Invalid("sample (NAL unit lengths)")
    );
}

#[test]
fn audio_only_and_unknown_formats() {
    // Audio only: cut on the audio track; every sample is a keyframe.
    let a = audio(100);
    let (file, _) = build(std::slice::from_ref(&a), true, false);
    let m = Movie::from_bytes(&file, &Limits::default()).unwrap();
    let plan = Plan::new(&m, SECOND / 2).unwrap();
    assert_eq!(plan.reference_track(), Some(0));
    assert!(plan.len() >= 4);
    // An `ac-3` entry: kept as Unknown with its format, samples indexed, no segments.
    let mut e = vec![0u8; 28];
    e[6..8].copy_from_slice(&1u16.to_be_bytes());
    let ac3 = bx(b"ac-3", &[&e, &bx(b"dac3", &[&[0x10, 0x3d, 0xc0]])]);
    let mut t = audio(10);
    t.stsd = bx(b"stsd", &[&full(0, 0), &be(&[1]), &ac3]);
    let (file, _) = build(&[t], true, false);
    let m = Movie::from_bytes(&file, &Limits::default()).unwrap();
    assert_eq!(&m.tracks[0].format, b"ac-3");
    assert_eq!(m.tracks[0].track.codec, Codec::Unknown);
    assert_eq!(m.tracks[0].track.sample_rate, 0);
    assert_eq!(m.tracks[0].index.len(), 10);
    assert!(Plan::new(&m, SECOND).unwrap().is_empty());
}

/// An hour at 60 fps with B-frames and AAC: the index stays small, and indexing is quick
/// (`cargo test -p akio-media --release --lib mp4::tests::index_an_hour -- --ignored --nocapture`
/// prints the times).
#[test]
#[ignore]
fn index_an_hour() {
    let n = 3600 * 60;
    let mut v = video(n, |i| {
        if i % 120 == 0 {
            60_000
        } else {
            3000 + (i % 97) as u32 * 31
        }
    });
    v.timescale = 15360;
    for (i, s) in v.samples.iter_mut().enumerate() {
        s.duration = 256;
        s.sync = i % 120 == 0;
        s.cts = [512, 1024, 0, 256][i % 4];
    }
    v.per_chunk = vec![30];
    let mut a = audio(3600 * 48000 / 1024);
    a.per_chunk = vec![45];
    let (file, _) = build(&[v, a], true, false);
    let t0 = std::time::Instant::now();
    let m = Movie::from_bytes(&file, &Limits::default()).unwrap();
    let parsed = t0.elapsed();
    let bytes = m.tracks[0].index.heap_bytes();
    assert!(bytes < 8 * n + 64 * 1024, "{bytes} bytes for {n} samples");
    let t1 = std::time::Instant::now();
    let walked: u64 = m
        .tracks
        .iter()
        .flat_map(|t| t.index.iter(0))
        .map(|s| u64::from(s.size))
        .sum();
    let walk = t1.elapsed();
    let t2 = std::time::Instant::now();
    let plan = Plan::new(&m, 6 * SECOND).unwrap();
    let planned = t2.elapsed();
    assert_eq!(plan.len(), 600);
    assert_eq!(
        walked,
        m.tracks.iter().map(|t| t.index.data_bytes()).sum::<u64>()
    );
    println!(
        "BENCH mp4_index_hour moov {} B, index {} B ({:.1} B/sample), parse {:?}, walk {:?}, plan {:?}",
        m.moov_size,
        m.index_bytes(),
        m.index_bytes() as f64 / f64::from(m.tracks.iter().map(|t| t.index.len()).sum::<u32>()),
        parsed,
        walk,
        planned
    );
}
