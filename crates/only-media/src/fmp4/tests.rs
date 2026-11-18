use super::{demux::parse_all, *};
use crate::{
    av::{Codec, MILLISECOND, Packet, SECOND, Track, Tracks, from_ticks},
    codec::{h264, opus},
};

/// Packets and tracks of a sample FLV file.
fn flv_sample(data: &[u8]) -> (Tracks, Vec<Packet>) {
    use crate::flv::{Decoder, Demuxer, Event};
    let mut dec = Decoder::new();
    let (mut tracks, mut pkts) = (None, Vec::new());
    for t in Demuxer::new().feed(data).expect("flv") {
        for e in dec.write(t.tag_type, t.ts, &t.body) {
            match e {
                Event::Tracks(t) => tracks = Some(t),
                Event::Packet(p) => pkts.push(p),
            }
        }
    }
    (tracks.expect("tracks"), pkts)
}

/// Packets and tracks of a sample transport stream.
fn ts_sample(data: &[u8]) -> (Tracks, Vec<Packet>) {
    use crate::mpegts::demux::{Demuxer, Event};
    let mut d = Demuxer::new();
    let (mut tracks, mut pkts) = (None, Vec::new());
    let mut emit = |e| match e {
        Event::Tracks(t) => tracks = Some(t),
        Event::Packet(p) => pkts.push(p),
    };
    d.feed(data, &mut emit).expect("ts");
    d.flush(&mut emit);
    (tracks.expect("tracks"), pkts)
}

/// Muxes `pkts` into an init segment and fragments of `per` packets each.
fn mux(tracks: &[Track], pkts: &[Packet], per: usize) -> Vec<u8> {
    let mut m = Muxer::new(tracks);
    let mut out = m.init_segment().to_vec();
    for chunk in pkts.chunks(per) {
        for p in chunk {
            assert!(m.write_packet(p));
        }
        let end = pkts.get(chunk.len()).map(|p| p.dts);
        write_styp(&mut out);
        assert!(m.flush(end, &mut out));
        assert!(!m.has_pending());
    }
    out
}

/// The packets of track `t`, in order.
fn of(pkts: &[Packet], t: usize) -> Vec<&Packet> {
    pkts.iter().filter(|p| p.track == t).collect()
}

/// Asserts the round trip kept every packet, times within half a tick of the track clock.
fn assert_round_trip(tracks: &[Track], input: &[Packet], got_tracks: &[Track], got: &[Packet]) {
    assert_eq!(got_tracks.len(), tracks.len());
    for (i, t) in tracks.iter().enumerate() {
        assert_eq!(got_tracks[i].codec, t.codec);
        let tol = SECOND / i64::from(t.clock_rate()) / 2 + 1;
        let (a, b) = (of(input, i), of(got, i));
        assert_eq!(a.len(), b.len(), "track {i}");
        assert!(!a.is_empty());
        for (x, y) in a.iter().zip(&b) {
            assert_eq!(x.data, y.data);
            assert_eq!(x.keyframe || !t.is_video(), y.keyframe);
            assert!((x.dts - y.dts).abs() <= tol, "{} vs {}", x.dts, y.dts);
            assert!((x.pts - y.pts).abs() <= 2 * tol, "{} vs {}", x.pts, y.pts);
        }
    }
}

#[test]
fn round_trip_h264_aac() {
    let (tracks, pkts) = flv_sample(include_bytes!("../../testdata/h264_aac.flv"));
    assert_eq!(tracks[0].codec, Codec::H264);
    assert_eq!(tracks[1].codec, Codec::Aac);
    let out = mux(&tracks, &pkts, 40);
    let (t, got) = parse_all(&out).expect("parse");
    let t = t.expect("tracks");
    assert_eq!(t, tracks, "tracks survive (configurations included)");
    assert_round_trip(&tracks, &pkts, &t, &got);
    // B-frames in the sample: composition offsets come back.
    assert!(got.iter().any(|p| p.pts != p.dts));
}

/// VP9 (`vp09` + `vpcC`) and AV1 (`av01` + `av1C`) with Opus; a VP8 track; a VP9 track
/// without a configuration that parses is left out.
#[test]
fn round_trip_vp9_av1_vp8() {
    for (name, data) in [
        ("vp9", &include_bytes!("../../testdata/vp9_opus.flv")[..]),
        ("av1", &include_bytes!("../../testdata/av1_opus.flv")[..]),
    ] {
        let (tracks, pkts) = flv_sample(data);
        let out = mux(&tracks, &pkts, 20);
        let (t, got) = parse_all(&out).expect(name);
        let t = t.expect("tracks");
        assert_eq!(t[0], tracks[0], "{name}");
        assert_round_trip(&tracks, &pkts, &t, &got);
        let entry: &[u8] = if name == "vp9" { b"vp09" } else { b"av01" };
        assert!(out.windows(4).any(|w| w == entry), "{name}");
    }
    let vp8 = Track::video_from_keyframe(
        Codec::Vp8,
        &[0x50, 0x2d, 0x00, 0x9d, 0x01, 0x2a, 0x40, 0x01, 0xf0, 0x00],
    )
    .expect("vp8");
    let pkts: Vec<Packet> = (0..10)
        .map(|i| {
            let key = i % 5 == 0;
            let data = if key {
                vec![0x50, 0x2d, 0, 0x9d, 1, 0x2a, 0x40, 1, 0xf0, 0]
            } else {
                vec![0x31, i]
            };
            Packet::new(
                0,
                i64::from(i) * 40 * MILLISECOND,
                i64::from(i) * 40 * MILLISECOND,
                key,
                data,
            )
        })
        .collect();
    let out = mux(std::slice::from_ref(&vp8), &pkts, 5);
    let (t, got) = parse_all(&out).expect("vp8");
    assert_eq!(t.expect("tracks")[0], vp8);
    assert_round_trip(
        std::slice::from_ref(&vp8),
        &pkts,
        std::slice::from_ref(&vp8),
        &got,
    );
    let bad = Track::new(Codec::Vp9, vec![1, 2]);
    assert!(!Muxer::new(&[bad]).has_tracks());
}

#[test]
fn round_trip_h265_aac_and_opus() {
    let (tracks, pkts) = flv_sample(include_bytes!("../../testdata/h265_aac.flv"));
    let out = mux(&tracks, &pkts, 25);
    let (t, got) = parse_all(&out).expect("parse");
    let t = t.expect("tracks");
    assert_eq!(t[0], tracks[0]);
    assert_round_trip(&tracks, &pkts, &t, &got);

    let (tracks, pkts) = ts_sample(include_bytes!("../../testdata/h265_opus.ts"));
    assert_eq!(tracks[0].codec, Codec::H265);
    assert_eq!(tracks[1].codec, Codec::Opus);
    let out = mux(&tracks, &pkts, 33);
    let (t, got) = parse_all(&out).expect("parse");
    let t = t.expect("tracks");
    assert_eq!(t[0], tracks[0]);
    assert_eq!(t[1].channels, tracks[1].channels.max(1));
    assert_eq!(t[1].sample_rate, 48_000);
    assert_round_trip(&tracks, &pkts, &t, &got);
}

#[test]
fn opus_head_and_dops() {
    let mut head = opus::Head::new(2);
    head.pre_skip = 0x0138;
    head.input_rate = 44_100;
    let tracks = vec![Track::audio(Codec::Opus, head.encode(), 48_000, 2)];
    let m = Muxer::new(&tracks);
    let init = m.init_segment();
    let at = init.windows(4).position(|w| w == b"dOps").expect("dOps");
    // Big-endian pre-skip and rate.
    assert_eq!(
        &init[at + 4..at + 15],
        &[0, 2, 0x01, 0x38, 0, 0, 0xac, 0x44, 0, 0, 0]
    );
    let (t, _) = parse_all(init).expect("parse");
    assert_eq!(t.expect("tracks")[0], tracks[0]);
    // Without an OpusHead: defaults (2 channels, pre-skip 312, 48 kHz).
    let m = Muxer::new(&[Track::audio(Codec::Opus, vec![], 48_000, 0)]);
    let init = m.init_segment();
    let at = init.windows(4).position(|w| w == b"dOps").expect("dOps");
    assert_eq!(
        &init[at + 4..at + 15],
        &[0, 2, 1, 56, 0, 0, 0xbb, 0x80, 0, 0, 0]
    );
    // The last Opus sample of a fragment lasts its TOC duration (20 ms = 960 ticks).
    let mut m = Muxer::new(&[Track::audio(Codec::Opus, vec![], 48_000, 2)]);
    let mut out = m.init_segment().to_vec();
    m.write_packet(&Packet::new(0, 0, 0, true, vec![0xfc, 1, 2]));
    m.flush(Some(5 * SECOND), &mut out);
    m.write_packet(&Packet::new(
        0,
        20 * MILLISECOND,
        20 * MILLISECOND,
        true,
        vec![0xfc],
    ));
    m.flush(None, &mut out);
    for trun in out
        .windows(4)
        .enumerate()
        .filter(|(_, w)| *w == b"trun")
        .map(|(i, _)| i)
    {
        assert_eq!(&out[trun + 16..trun + 20], &960u32.to_be_bytes());
    }
}

fn h264_track() -> Track {
    Track::video(
        Codec::H264,
        h264::Config::from_sets(&[0x67, 0x64, 0, 0x1f, 0xac], &[0x68, 0xee, 0x3c, 0x80]).encode(),
    )
}

fn frame(n: u8, key: bool) -> Vec<u8> {
    h264::to_avcc([&[if key { 0x65 } else { 0x41 }, n, n, n][..]])
}

/// B-frames: positive offsets use trun version 0, negative ones version 1 (signed).
#[test]
fn composition_offsets() {
    let tracks = vec![h264_track()];
    let tick = |n: i64| from_ticks(n * 3000, 90_000);
    // Decode order I P B B with presentation 1 4 2 3 (frames of 3000 ticks).
    let pkts: Vec<Packet> = [(0, 1, true), (1, 4, false), (2, 2, false), (3, 3, false)]
        .iter()
        .map(|&(d, p, k)| Packet::new(0, tick(d), tick(p), k, frame(d as u8, k)))
        .collect();
    let out = mux(&tracks, &pkts, 4);
    let trun = out.windows(4).position(|w| w == b"trun").expect("trun");
    assert_eq!(out[trun + 4], 0, "version 0 without negative offsets");
    let (t, got) = parse_all(&out).expect("parse");
    assert_round_trip(&tracks, &pkts, &t.expect("tracks"), &got);
    assert_eq!(got[1].pts - got[1].dts, tick(3));

    // The same with the first frame at pts == dts: the B-frames go negative.
    let pkts: Vec<Packet> = [(0, 0, true), (1, 3, false), (2, 1, false), (3, 2, false)]
        .iter()
        .map(|&(d, p, k)| Packet::new(0, tick(d), tick(p), k, frame(d as u8, k)))
        .collect();
    let out = mux(&tracks, &pkts, 4);
    let trun = out.windows(4).position(|w| w == b"trun").expect("trun");
    assert_eq!(out[trun + 4], 1, "version 1 with negative offsets");
    let (t, got) = parse_all(&out).expect("parse");
    assert_round_trip(&tracks, &pkts, &t.expect("tracks"), &got);
    assert!((got[2].pts - got[2].dts + tick(1)).abs() <= 1);
    assert!(got[0].keyframe && !got[1].keyframe);
}

/// Sample durations: from the next sample, the fragment end for the last video sample,
/// 1024 for the last AAC frame; tfdt is absolute.
#[test]
fn durations_and_decode_times() {
    let tracks = vec![h264_track(), Track::aac(vec![0x11, 0x90])]; // AAC-LC 48 kHz stereo
    let mut m = Muxer::new(&tracks);
    let mut out = Vec::new();
    let v = |ms: i64, k: bool| Packet::new(0, ms * MILLISECOND, ms * MILLISECOND, k, frame(1, k));
    let a = |ms: i64| Packet::new(1, ms * MILLISECOND, ms * MILLISECOND, true, vec![0x21; 10]);
    for p in [
        v(1000, true),
        a(1000),
        v(1040, false),
        a(1021),
        v(1080, false),
    ] {
        assert!(m.write_packet(&p));
    }
    m.flush(Some(1100 * MILLISECOND), &mut out);
    let (_, got) = {
        let mut all = m.init_segment().to_vec();
        all.extend_from_slice(&out);
        parse_all(&all).expect("parse")
    };
    assert_eq!(got.len(), 5);
    // Read the truns: video durations 3600, 3600, 1800 (until the end at 1100 ms).
    let truns: Vec<usize> = out
        .windows(4)
        .enumerate()
        .filter(|(_, w)| *w == b"trun")
        .map(|(i, _)| i)
        .collect();
    let u32_at =
        |out: &[u8], i: usize| u32::from_be_bytes([out[i], out[i + 1], out[i + 2], out[i + 3]]);
    let video = truns[0];
    assert_eq!(u32_at(&out, video + 8), 3);
    let first = video + 16; // version/flags, count, data offset
    assert_eq!(
        [
            u32_at(&out, first),
            u32_at(&out, first + 12),
            u32_at(&out, first + 24)
        ],
        [3600, 3600, 1800]
    );
    let audio = truns[1] + 16;
    assert_eq!(
        [u32_at(&out, audio), u32_at(&out, audio + 12)],
        [1008, 1024]
    );
    // tfdt carries the absolute decode time (1 s = 90000 / 48000 ticks).
    let tfdts: Vec<u64> = out
        .windows(4)
        .enumerate()
        .filter(|(_, w)| *w == b"tfdt")
        .map(|(i, _)| {
            let mut b = [0u8; 8];
            b.copy_from_slice(&out[i + 8..i + 16]);
            u64::from_be_bytes(b)
        })
        .collect();
    assert_eq!(tfdts, [90_000, 48_000]);
    // A single video sample with no end: the previous duration.
    m.write_packet(&v(1100, false));
    let at = out.len();
    m.flush(None, &mut out);
    let t = at
        + out[at..]
            .windows(4)
            .position(|w| w == b"trun")
            .expect("trun");
    assert_eq!(u32_at(&out, t + 16), 1800);
}

/// Every box size is exact: children fill their parents, top-level boxes the buffer.
#[test]
fn box_sizes_are_exact() {
    fn walk(b: &[u8], seen: &mut Vec<[u8; 4]>) {
        let mut p = 0;
        while p < b.len() {
            assert!(b.len() - p >= 8, "short header at {p}");
            let size = u32::from_be_bytes([b[p], b[p + 1], b[p + 2], b[p + 3]]) as usize;
            let typ = [b[p + 4], b[p + 5], b[p + 6], b[p + 7]];
            assert!(size >= 8 && p + size <= b.len(), "{typ:?} size {size}");
            seen.push(typ);
            let body = &b[p + 8..p + size];
            let container = matches!(
                &typ,
                b"moov"
                    | b"trak"
                    | b"mdia"
                    | b"minf"
                    | b"dinf"
                    | b"stbl"
                    | b"mvex"
                    | b"moof"
                    | b"traf"
            );
            // Boxes with fields before their children.
            let skip = match &typ {
                b"stsd" | b"dref" => Some(8),
                b"avc1" | b"hvc1" => Some(78),
                b"mp4a" | b"Opus" => Some(28),
                _ if container => Some(0),
                _ => None,
            };
            if let Some(k) = skip {
                walk(&body[k..], seen);
            }
            let fixed: Option<usize> = match &typ {
                b"ftyp" | b"styp" => Some(28),
                b"mvhd" => Some(108),
                b"tkhd" => Some(92),
                b"mdhd" => Some(32),
                b"vmhd" => Some(20),
                b"smhd" => Some(16),
                b"mfhd" => Some(16),
                b"tfhd" => Some(16),
                b"tfdt" => Some(20),
                b"trex" => Some(32),
                b"stsz" => Some(20),
                b"stts" | b"stsc" | b"stco" => Some(16),
                _ => None,
            };
            if let Some(f) = fixed {
                assert_eq!(size, f, "{}", String::from_utf8_lossy(&typ));
            }
            p += size;
        }
        assert_eq!(p, b.len());
    }
    let (tracks, pkts) = flv_sample(include_bytes!("../../testdata/h264_aac.flv"));
    let out = mux(&tracks, &pkts, 50);
    let mut seen = Vec::new();
    walk(&out, &mut seen);
    for t in [
        b"ftyp", b"moov", b"trak", b"stsd", b"avcC", b"esds", b"styp", b"moof", b"mdat",
    ] {
        assert!(seen.contains(t), "{}", String::from_utf8_lossy(t));
    }
    // trun: 20 header bytes + 16 per sample (with composition offsets) or 12.
    let mut p = out.windows(4).position(|w| w == b"moof").expect("moof") - 4;
    while let Some(i) = out[p..].windows(4).position(|w| w == b"trun") {
        let at = p + i - 4;
        let size = u32::from_be_bytes([out[at], out[at + 1], out[at + 2], out[at + 3]]) as usize;
        let flags = u32::from_be_bytes([0, out[at + 9], out[at + 10], out[at + 11]]);
        let n = u32::from_be_bytes([out[at + 12], out[at + 13], out[at + 14], out[at + 15]]);
        let per = if flags & TRUN_CTS != 0 { 16 } else { 12 };
        assert_eq!(size, 20 + per * n as usize);
        p = at + size;
    }
    // The init segment of an H.264 + AAC stream: exact length.
    let m = Muxer::new(&tracks);
    let init = m.init_segment();
    let avcc = tracks[0].config.len();
    // trak tkhd mdia mdhd hdlr minf vmhd dinf stbl stsd avc1 avcC, then stts stsc stsz stco.
    let video_trak = 8 + 92 + 8 + 32 + 45 + 8 + 20 + 36 + 8 + 16 + 86 + 8 + avcc + 68;
    let esds = 12 + 2 + 3 + 2 + 13 + 2 + tracks[1].config.len() + 3;
    let audio_trak = 8 + 92 + 8 + 32 + 45 + 8 + 16 + 36 + 8 + 16 + 36 + esds + 68;
    assert_eq!(
        init.len(),
        28 + 8 + 108 + video_trak + audio_trak + 8 + 2 * 32
    );
}

#[test]
fn uncarried_tracks_are_left_out() {
    let tracks = vec![
        Track::audio(Codec::Pcmu, vec![], 8000, 1),
        h264_track(),
        Track::new(Codec::Mp3, vec![]),
    ];
    let mut m = Muxer::new(&tracks);
    assert!(m.has_tracks());
    assert!(!m.carries(0) && m.carries(1) && !m.carries(2) && !m.carries(3));
    assert!(!m.write_packet(&Packet::new(0, 0, 0, true, vec![1])));
    assert!(!m.flush(None, &mut Vec::new()));
    assert!(m.write_packet(&Packet::new(1, 0, 0, true, frame(0, true))));
    let mut out = m.init_segment().to_vec();
    assert!(m.flush(None, &mut out));
    let (t, got) = parse_all(&out).expect("parse");
    // Track IDs are dense: the demuxer sees one track.
    assert_eq!(t.expect("tracks").len(), 1);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].track, 0);
    assert!(!Muxer::new(&[Track::new(Codec::Pcma, vec![])]).has_tracks());
}

/// Truncated, oversized or inconsistent input is an error, never a panic.
#[test]
fn parser_rejects_bad_input() {
    let (tracks, pkts) = flv_sample(include_bytes!("../../testdata/h264_aac.flv"));
    let out = mux(&tracks, &pkts[..60], 30);
    // Every prefix: no panic; one cut inside a box is an error.
    let mut boundaries = Vec::new();
    let mut p = 0;
    while p < out.len() {
        boundaries.push(p);
        p += u32::from_be_bytes([out[p], out[p + 1], out[p + 2], out[p + 3]]) as usize;
    }
    for n in 0..out.len() {
        let r = parse_all(&out[..n]);
        if !boundaries.contains(&n) {
            assert!(r.is_err(), "prefix {n} accepted");
        }
    }
    // A box larger than what is left.
    let mut bad = out.clone();
    bad[0..4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(parse_all(&bad).err(), Some(Fmp4Error::Truncated));
    // A 64-bit size past the end.
    let mut bad = vec![0, 0, 0, 1, b'f', b'r', b'e', b'e'];
    bad.extend_from_slice(&(1u64 << 40).to_be_bytes());
    assert_eq!(parse_all(&bad).err(), Some(Fmp4Error::Truncated));
    // A size smaller than the header.
    assert_eq!(
        parse_all(&[0, 0, 0, 4, b'f', b'r', b'e', b'e']).err(),
        Some(Fmp4Error::Truncated)
    );
    // A fragment before any moov.
    let init_len = Muxer::new(&tracks).init_segment().len();
    assert!(parse_all(&out[init_len..]).is_err());
    // A trun claiming more samples than it has entries.
    let mut bad = out.clone();
    let t = bad.windows(4).position(|w| w == b"trun").expect("trun");
    bad[t + 8..t + 12].copy_from_slice(&0x1000_0000u32.to_be_bytes());
    assert_eq!(parse_all(&bad).err(), Some(Fmp4Error::Truncated));
    // A sample size pointing past the end.
    let mut bad = out.clone();
    bad[t + 20..t + 24].copy_from_slice(&0x7fff_0000u32.to_be_bytes());
    assert_eq!(parse_all(&bad).err(), Some(Fmp4Error::Truncated));
    // A data offset pointing backwards before the input.
    let mut bad = out.clone();
    bad[t + 12..t + 16].copy_from_slice(&(-0x10_0000i32).to_be_bytes());
    assert!(parse_all(&bad).is_err());
    // Samples all pointing at the same bytes: bounded by the input size.
    let mut bad = out[..init_len].to_vec();
    bad.extend_from_slice(&overlapping_fragment(2000));
    assert_eq!(
        parse_all(&bad).err(),
        Some(Fmp4Error::Limit("sample bytes"))
    );
    let mut ok = out[..init_len].to_vec();
    ok.extend_from_slice(&overlapping_fragment(1));
    let (_, got) = parse_all(&ok).expect("one sample");
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].data.len(), 4096);
    // An unknown track ID.
    let mut bad = out;
    let t = bad.windows(4).position(|w| w == b"tfhd").expect("tfhd");
    bad[t + 8..t + 12].copy_from_slice(&99u32.to_be_bytes());
    assert!(parse_all(&bad).is_err());
}

/// A moof whose `truns` (one sample each, 4096 bytes by the tfhd default) all point at the
/// start of one 4096-byte mdat.
fn overlapping_fragment(truns: usize) -> Vec<u8> {
    let traf_len = 8 + 20 + 20 * truns;
    let moof_len = 8 + 16 + traf_len;
    let mut f = Vec::new();
    f.extend_from_slice(&(moof_len as u32).to_be_bytes());
    f.extend_from_slice(b"moof");
    f.extend_from_slice(&[0, 0, 0, 16]);
    f.extend_from_slice(b"mfhd");
    f.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1]);
    f.extend_from_slice(&(traf_len as u32).to_be_bytes());
    f.extend_from_slice(b"traf");
    f.extend_from_slice(&[0, 0, 0, 20]);
    f.extend_from_slice(b"tfhd");
    f.extend_from_slice(&[0, 0x02, 0, 0x10, 0, 0, 0, 1]); // base is moof, default size
    f.extend_from_slice(&4096u32.to_be_bytes());
    for _ in 0..truns {
        f.extend_from_slice(&[0, 0, 0, 20]);
        f.extend_from_slice(b"trun");
        f.extend_from_slice(&[0, 0, 0, 1]); // data offset only
        f.extend_from_slice(&1u32.to_be_bytes());
        f.extend_from_slice(&((moof_len + 8) as u32).to_be_bytes());
    }
    f.extend_from_slice(&(8 + 4096u32).to_be_bytes());
    f.extend_from_slice(b"mdat");
    f.resize(f.len() + 4096, 0);
    f
}

#[test]
fn styp_shape() {
    let mut s = Vec::new();
    write_styp(&mut s);
    assert_eq!(s.len(), 28);
    assert_eq!(&s[4..8], b"styp");
}
