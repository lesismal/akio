//! Codec tests: pion cross-checks (byte-exact, via hashes computed by a Go program over the
//! same generated inputs), browser-like payloads, round trips and frame assembly.

use std::time::{Duration, Instant};

use super::fuzz::{expected_output, roundtrip};
use super::*;

/// splitmix64, mirrored in the Go cross-check program.
pub(crate) struct Rng(u64);

impl Rng {
    pub(crate) fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    pub(crate) fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
    /// Bytes without zeros (no start codes or trailing zeros in NAL units).
    pub(crate) fn nz(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| (1 + self.next() % 255) as u8).collect()
    }
}

struct Fnv(u64);

impl Fnv {
    fn new() -> Self {
        Fnv(0xcbf2_9ce4_8422_2325)
    }
    fn write(&mut self, b: &[u8]) {
        for &c in b {
            self.0 = (self.0 ^ u64::from(c)).wrapping_mul(0x100_0000_01b3);
        }
    }
    fn pkt(&mut self, b: &[u8]) {
        self.write(&(b.len() as u32).to_be_bytes());
        self.write(b);
    }
}

fn leb(v: usize) -> Vec<u8> {
    let mut out = Vec::new();
    av1::write_leb128(&mut out, v);
    out
}

fn annexb(nals: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, n) in nals.iter().enumerate() {
        out.extend_from_slice(if i % 2 == 0 {
            &[0, 0, 0, 1][..]
        } else {
            &[0, 0, 1][..]
        });
        out.extend_from_slice(n);
    }
    out
}

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

fn payloads(v: Vec<(Vec<u8>, bool)>) -> Vec<Vec<u8>> {
    v.into_iter().map(|(p, _)| p).collect()
}

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// ---- sample frames (also used for fuzz seeds) ----

pub(crate) fn vp8_keyframe(len: usize) -> Vec<u8> {
    let mut f = vec![0x10, 0x02, 0x00, 0x9d, 0x01, 0x2a, 0x80, 0x02, 0xe0, 0x01];
    f.extend(Rng(10).bytes(len.saturating_sub(f.len())));
    f
}

pub(crate) fn vp9_keyframe(w: u16, h: u16, len: usize) -> Vec<u8> {
    let (w1, h1) = (w - 1, h - 1);
    let mut f = vec![
        0x82,
        0x49,
        0x83,
        0x42,
        (w1 >> 12) as u8,
        (w1 >> 4) as u8,
        (((w1 & 0xf) << 4) | (h1 >> 12)) as u8,
        (h1 >> 4) as u8,
        ((h1 & 0xf) << 4) as u8,
    ];
    f.extend(Rng(11).bytes(len));
    f
}

pub(crate) fn h264_keyframe(idr_len: usize) -> Vec<u8> {
    let mut r = Rng(12);
    annexb(&[
        vec![0x09, 0xf0],
        cat(&[&[0x67, 0x42, 0xc0, 0x1f], &r.nz(8)]),
        cat(&[&[0x68, 0xce], &r.nz(2)]),
        cat(&[&[0x65, 0x88], &r.nz(idr_len)]),
    ])
}

pub(crate) fn h265_keyframe(idr_len: usize) -> Vec<u8> {
    let mut r = Rng(13);
    annexb(&[
        cat(&[&[0x40, 0x01], &r.nz(20)]),
        cat(&[&[0x42, 0x01], &r.nz(30)]),
        cat(&[&[0x44, 0x01], &r.nz(5)]),
        cat(&[&[0x26, 0x01], &r.nz(idr_len)]),
    ])
}

pub(crate) fn av1_temporal_unit(key: bool, len: usize) -> Vec<u8> {
    let mut r = Rng(14);
    let mut tu = vec![0x12, 0x00];
    if key {
        let sh = r.bytes(12);
        tu.extend(cat(&[&[0x0a], &leb(sh.len()), &sh]));
    }
    let f = r.bytes(len);
    tu.extend(cat(&[&[0x32], &leb(f.len()), &f]));
    tu
}

// ---- pion cross-checks (hashes printed by the Go program over identical inputs) ----

#[test]
fn pion_vp8_byte_exact() {
    let mut r = Rng(1);
    let mut h = Fnv::new();
    // pion uses a 7-bit PictureID below 128; start where both use 15 bits.
    let mut p = Vp8Packetizer::new(300);
    for mtu in [5, 6, 7, 8, 13, 100, 1200, 1500] {
        for size in [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 15, 16, 17, 100, 1000, 1195, 1196, 1197, 1200, 1201,
            4000,
        ] {
            let f = r.bytes(size);
            for pl in payloads(p.packetize(mtu, &f)) {
                h.pkt(&pl);
            }
        }
    }
    assert_eq!(h.0, 0xca72_8149_c238_1889);
}

#[test]
fn pion_h264_byte_exact() {
    let mut r = Rng(2);
    let (mut h, mut hd) = (Fnv::new(), Fnv::new());
    let mut p = H264Packetizer::new();
    let mut d = H264Depacketizer::new();
    for mtu in [40usize, 100, 576, 1200] {
        for k in 0..60usize {
            let aud = vec![0x09, 0xf0];
            let sps = cat(&[&[0x67], &r.nz(9 + k % 7)]);
            let pps = cat(&[&[0x68], &r.nz(3 + k % 3)]);
            let idr = cat(&[&[0x65], &r.nz(mtu - 5 + k * 7 - 1)]);
            let frames = [
                annexb(&[aud, sps, pps, idr]),
                annexb(&[cat(&[&[0x41], &r.nz((k * 37) % (3 * mtu) + 1)])]),
                annexb(&[
                    cat(&[&[0x41], &r.nz(mtu / 2 + 2 + k)]),
                    cat(&[&[0x01], &r.nz(mtu / 2 + 2 + 2 * k)]),
                ]),
            ];
            for f in &frames {
                let mut out = Vec::new();
                for pl in payloads(p.packetize(mtu, f)) {
                    h.pkt(&pl);
                    d.depacketize(&pl, &mut out).unwrap();
                }
                hd.pkt(&out);
            }
        }
    }
    assert_eq!(h.0, 0x151f_c41f_16c4_9e21, "packetizer");
    assert_eq!(hd.0, 0x5c6b_2c4c_b921_11a2, "depacketizer");
}

#[test]
fn pion_h265_byte_exact() {
    // pion sends a NAL unit of mtu-1 or mtu bytes as fragments (it reserves DONL room); the
    // inputs avoid those two sizes, where this packetizer sends a single NAL unit packet.
    let mut r = Rng(3);
    let mut h = Fnv::new();
    let mut p = H265Packetizer::new();
    for mtu in [40usize, 100, 576, 1200] {
        let size = |t: usize| if t > mtu - 2 && t <= mtu { mtu - 3 } else { t };
        for k in 0..60usize {
            let vps = cat(&[&[0x40, 0x01], &r.nz(10 + k % 5)]);
            let sps = cat(&[&[0x42, 0x01], &r.nz(20 + k % 9)]);
            let pps = cat(&[&[0x44, 0x01], &r.nz(4 + k % 3)]);
            let idr = cat(&[&[0x26, 0x01], &r.nz(size(mtu - 30 + k * 13) - 2)]);
            let f1 = annexb(&[vps, sps, pps, idr]);
            let mut small = Vec::new();
            for i in 0..=k % 4 {
                small.push(cat(&[
                    &[0x4e, 0x01],
                    &r.nz(size(7 + (k * 7 + i * 11) % 45) - 2),
                ]));
            }
            small.push(cat(&[
                &[0x02, 0x01],
                &r.nz(size((k * 53) % (3 * mtu) + 3) - 2),
            ]));
            let f2 = annexb(&small);
            for f in [f1, f2] {
                for pl in payloads(p.packetize(mtu, &f)) {
                    h.pkt(&pl);
                }
            }
        }
    }
    assert_eq!(h.0, 0x2da2_c89b_8577_c542);
}

#[test]
fn pion_av1_byte_exact() {
    let mut r = Rng(4);
    let (mut h, mut hd) = (Fnv::new(), Fnv::new());
    let mut p = Av1Packetizer::new();
    for mtu in [2usize, 3, 4, 5, 10, 50, 100, 300, 1200] {
        for k in 0..40usize {
            let mut tu = vec![0x12, 0x00];
            if k % 5 == 0 {
                let sh = r.bytes(10 + k % 7);
                tu.extend(cat(&[&[0x0a], &leb(sh.len()), &sh]));
            }
            if k % 6 == 1 {
                let md = r.bytes(3 + k % 4);
                tu.extend(cat(&[&[0x2a], &leb(md.len()), &md]));
            }
            for i in 0..=k % 3 {
                let pl = r.bytes((k * 97 + i * 31) % 2500);
                if k % 4 == 3 {
                    let ext = (((k % 2) << 5) | ((i % 2) << 3)) as u8;
                    tu.extend(cat(&[&[0x36, ext], &leb(pl.len()), &pl]));
                } else {
                    tu.extend(cat(&[&[0x32], &leb(pl.len()), &pl]));
                }
            }
            let mut d = Av1Depacketizer::new();
            let mut out = Vec::new();
            for pl in payloads(p.packetize(mtu, &tu)) {
                h.pkt(&pl);
                d.depacketize(&pl, &mut out).unwrap();
            }
            hd.pkt(&out);
            assert_eq!(out, expected_output(CodecKind::Av1, &tu));
        }
    }
    assert_eq!(h.0, 0x8ef9_0b37_e5f4_b103, "packetizer");
    assert_eq!(hd.0, 0x2381_d724_df0b_6bc7, "depacketizer");
}

#[test]
fn pion_vp9_byte_exact() {
    let mut r = Rng(5);
    let mut h = Fnv::new();
    let mut p = Vp9Packetizer::new(1234);
    for mtu in [12usize, 13, 20, 100, 1200] {
        for k in 0..30usize {
            let size = 5 + (k * 211) % 3000;
            let f = if k % 3 == 0 {
                let w1 = (r.next() % 4096) as u16;
                let h1 = (r.next() % 4096) as u16;
                let mut f = vp9_header(w1, h1);
                f.extend(r.bytes(size));
                f
            } else {
                cat(&[&[0x86], &r.bytes(size)])
            };
            for pl in payloads(p.packetize(mtu, &f)) {
                h.pkt(&pl);
            }
        }
    }
    assert_eq!(h.0, 0xe673_632a_a394_4375);
}

fn vp9_header(w1: u16, h1: u16) -> Vec<u8> {
    vec![
        0x82,
        0x49,
        0x83,
        0x42,
        (w1 >> 12) as u8,
        (w1 >> 4) as u8,
        (((w1 & 0xf) << 4) | (h1 >> 12)) as u8,
        (h1 >> 4) as u8,
        ((h1 & 0xf) << 4) as u8,
    ]
}

// ---- literal vectors and browser-like payloads ----

#[test]
fn vp8_descriptor_bytes() {
    let mut p = Vp8Packetizer::new(0x1234);
    let out = p.packetize(8, &[1, 2, 3, 4, 5, 6]);
    assert_eq!(
        out,
        vec![
            (vec![0x90, 0x80, 0x92, 0x34, 1, 2, 3, 4], false),
            (vec![0x80, 0x80, 0x92, 0x34, 5, 6], true),
        ]
    );
    assert_eq!(p.picture_id(), 0x1235);
    let mut p = Vp8Packetizer::new(0x7fff);
    let out = p.packetize(100, &[9]);
    assert_eq!(out[0].0, vec![0x90, 0x80, 0xff, 0xff, 9]);
    assert_eq!(p.picture_id(), 0);
}

#[test]
fn vp8_browser_descriptors() {
    let d = Vp8Depacketizer::new();
    // Chrome: X=1 S=1 PID=0; I=1 L=1 T=1; 15-bit PictureID; TL0PICIDX; TID=1 Y=1.
    let p = [0x90, 0xe0, 0x81, 0x23, 0x07, 0x60, 0x10, 0x02, 0x00];
    let mut out = Vec::new();
    Vp8Depacketizer::new().depacketize(&p, &mut out).unwrap();
    assert_eq!(out, [0x10, 0x02, 0x00]);
    assert!(d.is_frame_start(&p));
    assert!(d.is_keyframe(&p));
    // 7-bit PictureID, K only, inter frame (P=1).
    let p = [0x90, 0x90, 0x05, 0x1f, 0x31, 0xaa];
    let mut out = Vec::new();
    Vp8Depacketizer::new().depacketize(&p, &mut out).unwrap();
    assert_eq!(out, [0x31, 0xaa]);
    assert!(!d.is_keyframe(&p));
    // No X; continuation (S=0) and second partition (PID=1) are not frame starts.
    assert!(d.is_frame_start(&[0x10, 0x00]));
    assert!(!d.is_frame_start(&[0x00, 0x00]));
    assert!(!d.is_frame_start(&[0x11, 0x00]));
    assert!(!d.is_keyframe(&[0x00, 0x00]));
    // Truncated extensions.
    for p in [
        &[][..],
        &[0x80],
        &[0x80, 0x80],
        &[0x80, 0x80, 0x80],
        &[0x80, 0x40],
        &[0x80, 0x20],
    ] {
        assert_eq!(
            Vp8Depacketizer::new().depacketize(p, &mut Vec::new()),
            Err(CodecError::Truncated),
            "{p:?}"
        );
    }
}

#[test]
fn h264_stap_a_from_browser() {
    // STAP-A with SPS and PPS as Chrome sends ahead of an IDR.
    let p = hex("78 000b 6742c01f8c8d40501e9008 0004 68ce3c80");
    let d = H264Depacketizer::new();
    assert!(d.is_frame_start(&p));
    assert!(d.is_keyframe(&p));
    let mut out = Vec::new();
    H264Depacketizer::new().depacketize(&p, &mut out).unwrap();
    assert_eq!(
        out,
        hex("00000001 6742c01f8c8d40501e9008 00000001 68ce3c80")
    );
    // Truncated STAP-A.
    let mut out = Vec::new();
    assert_eq!(
        H264Depacketizer::new().depacketize(&[0x78, 0x00, 0x05, 0x67], &mut out),
        Err(CodecError::Truncated)
    );
    // FU-A continuation without its start.
    assert_eq!(
        H264Depacketizer::new().depacketize(&[0x7c, 0x05, 1, 2], &mut Vec::new()),
        Err(CodecError::FragmentWithoutStart)
    );
    // FU-B is ignored, STAP-B is unsupported.
    assert_eq!(
        H264Depacketizer::new().depacketize(&[0x1d, 0x85, 0, 0, 1], &mut Vec::new()),
        Ok(())
    );
    assert_eq!(
        H264Depacketizer::new().depacketize(&[0x19, 0, 0], &mut Vec::new()),
        Err(CodecError::UnsupportedType(25))
    );
}

#[test]
fn h264_fu_a_and_aud_drop() {
    let nal = cat(&[&[0x65], &[7u8; 10]]);
    let frame = annexb(&[vec![0x09, 0x10], nal]);
    let out = H264Packetizer::new().packetize(6, &frame);
    assert_eq!(
        out,
        vec![
            (vec![0x7c, 0x85, 7, 7, 7, 7], false),
            (vec![0x7c, 0x05, 7, 7, 7, 7], false),
            (vec![0x7c, 0x45, 7, 7], true),
        ]
    );
    let d = H264Depacketizer::new();
    assert!(d.is_frame_start(&out[0].0) && d.is_keyframe(&out[0].0));
    assert!(!d.is_frame_start(&out[1].0) && !d.is_keyframe(&out[1].0));
    // Small units aggregate: SPS, PPS and a small IDR in one STAP-A (NRI = max).
    let frame = annexb(&[vec![0x67, 1], vec![0x68, 2], vec![0x25, 3]]);
    assert_eq!(
        H264Packetizer::new().packetize(1200, &frame),
        vec![(
            vec![0x78, 0, 2, 0x67, 1, 0, 2, 0x68, 2, 0, 2, 0x25, 3],
            true
        )]
    );
}

#[test]
fn h265_packets() {
    // AP of VPS and SPS, then FU of a large IDR.
    let vps = vec![0x40, 0x01, 0xaa];
    let sps = vec![0x42, 0x01, 0xbb];
    let idr = cat(&[&[0x26, 0x01], &[9u8; 9]]);
    let out = H265Packetizer::new().packetize(10, &annexb(&[vps, sps, idr]));
    assert_eq!(out.len(), 4);
    // mtu 10: AP needs 2 + 5 + 5 = 12 bytes, so VPS and SPS go as single NAL unit packets.
    assert_eq!(out[0], (vec![0x40, 0x01, 0xaa], false));
    assert_eq!(out[1], (vec![0x42, 0x01, 0xbb], false));
    assert_eq!(out[2], (vec![0x62, 0x01, 0x93, 9, 9, 9, 9, 9, 9, 9], false));
    assert_eq!(out[3], (vec![0x62, 0x01, 0x53, 9, 9], true));
    let out = H265Packetizer::new().packetize(
        12,
        &annexb(&[vec![0x40, 0x01, 0xaa], vec![0x42, 0x01, 0xbb]]),
    );
    assert_eq!(
        out,
        vec![(
            vec![0x60, 0x01, 0, 3, 0x40, 0x01, 0xaa, 0, 3, 0x42, 0x01, 0xbb],
            true
        )]
    );
    let d = H265Depacketizer::new();
    assert!(d.is_keyframe(&out[0].0));
    let mut buf = Vec::new();
    H265Depacketizer::new()
        .depacketize(&out[0].0, &mut buf)
        .unwrap();
    assert_eq!(buf, hex("00000001 4001aa 00000001 4201bb"));
    assert_eq!(
        H265Depacketizer::new().depacketize(&[0x64, 0x01, 0], &mut Vec::new()),
        Err(CodecError::UnsupportedType(50))
    );
    assert_eq!(
        H265Depacketizer::new().depacketize(&[0x62, 0x01, 0x13, 1], &mut Vec::new()),
        Err(CodecError::FragmentWithoutStart)
    );
}

#[test]
fn vp9_flexible_and_ss_parse() {
    let d = Vp9Depacketizer::new();
    // Flexible mode: I (7-bit), P, L, F, B, E; one P_DIFF with N=1 then one with N=0.
    let p = [0xfc, 0x05, 0x02, 0x03, 0x04, 0xde, 0xad];
    let mut out = Vec::new();
    Vp9Depacketizer::new().depacketize(&p, &mut out).unwrap();
    assert_eq!(out, [0xde, 0xad]);
    assert!(
        !d.is_frame_start(&p),
        "spatial layer 1 does not start a picture"
    );
    // Keyframe from pion-style non-flexible with SS (as our packetizer writes).
    let pk = Vp9Packetizer::new(5).packetize(1200, &vp9_header(639, 479));
    let p = &pk[0].0;
    assert_eq!(
        &p[..11],
        &[
            0x8f, 0x80, 0x05, 0x18, 0x02, 0x80, 0x01, 0xe0, 0x01, 0x14, 0x01
        ]
    );
    assert!(d.is_keyframe(p) && d.is_frame_start(p) && d.is_frame_end(p, false));
    // SS with N_G pictures and R references.
    let p = [0x8a, 0x01, 0x08, 0x02, 0x24, 0x01, 0x02, 0x55];
    let mut out = Vec::new();
    Vp9Depacketizer::new().depacketize(&p, &mut out).unwrap();
    assert_eq!(out, [0x55]);
    assert_eq!(
        Vp9Depacketizer::new().depacketize(&[0x92, 0x81], &mut Vec::new()),
        Err(CodecError::Truncated)
    );
    assert!(matches!(
        Vp9Depacketizer::new().depacketize(&[0x50, 0x03, 0x03, 0x03, 0x00], &mut Vec::new()),
        Err(CodecError::Malformed(_))
    ));
}

#[test]
fn av1_depacketizer_errors_and_keyframe() {
    let d = Av1Depacketizer::new();
    assert!(d.is_keyframe(&[0x18, 0x0a, 0x00]));
    assert!(d.is_keyframe(&[0x10, 0x0a, 0x00]));
    assert!(!d.is_keyframe(&[0x10, 0x32, 0x00]));
    assert!(d.is_frame_start(&[0x10, 0x32]) && !d.is_frame_start(&[0x90, 0x32]));
    let mut a = Av1Depacketizer::new();
    assert!(matches!(
        a.depacketize(&[0x88, 0x00], &mut Vec::new()),
        Err(CodecError::Malformed(_))
    ));
    assert_eq!(
        a.depacketize(&[0x90, 0x01], &mut Vec::new()),
        Err(CodecError::FragmentWithoutStart)
    );
    assert!(matches!(
        a.depacketize(&[0x30, 0x01, 0x32], &mut Vec::new()),
        Err(CodecError::Malformed(_))
    ));
    assert_eq!(
        a.depacketize(&[0x00, 0x05, 0x32], &mut Vec::new()),
        Err(CodecError::Truncated)
    );
    // A fragmented OBU across two packets gets its size field back.
    let mut out = Vec::new();
    a.depacketize(&[0x50, 0x30, 1, 2], &mut out).unwrap();
    assert!(out.is_empty());
    a.depacketize(&[0x90, 3, 4], &mut out).unwrap();
    assert_eq!(out, [0x32, 0x04, 1, 2, 3, 4]);
}

// ---- round trips ----

#[test]
fn round_trips_all_codecs() {
    let mut r = Rng(99);
    let mtus = [1usize, 2, 3, 4, 5, 6, 7, 12, 13, 50, 100, 255, 1200, 1500];
    for kind in CodecKind::ALL {
        for &mtu in &mtus {
            let mut sizes = vec![1usize, 2, 3, 4, 5, 10, 100, 3000];
            for d in [
                mtu.saturating_sub(4),
                mtu.saturating_sub(1),
                mtu,
                mtu + 1,
                2 * mtu,
                3 * mtu + 7,
            ] {
                sizes.push(d.max(1));
            }
            for &size in &sizes {
                let frames = [
                    r.bytes(size),
                    match kind {
                        CodecKind::H264 => h264_keyframe(size),
                        CodecKind::H265 => h265_keyframe(size),
                        CodecKind::Av1 => av1_temporal_unit(size % 2 == 0, size),
                        CodecKind::Vp9 => vp9_keyframe(320, 240, size),
                        _ => vp8_keyframe(size),
                    },
                ];
                for f in &frames {
                    let exp = expected_output(kind, f);
                    match roundtrip(kind, mtu, f) {
                        Some(got) => assert!(got == exp, "{kind:?} mtu {mtu} size {size}"),
                        None => {
                            assert!(exp.is_empty() || mtu < 12, "{kind:?} mtu {mtu} size {size}");
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn many_nals_and_obus() {
    let mut r = Rng(7);
    let nals: Vec<Vec<u8>> = (0..200)
        .map(|i| cat(&[&[if i % 2 == 0 { 0x41 } else { 0x06 }], &r.nz(i * 13 % 700)]))
        .collect();
    let frame = annexb(&nals);
    for mtu in [20, 300, 1200] {
        assert_eq!(
            roundtrip(CodecKind::H264, mtu, &frame),
            Some(expected_output(CodecKind::H264, &frame))
        );
    }
    let hn: Vec<Vec<u8>> = (0..200)
        .map(|i| cat(&[&[0x02, 0x01], &r.nz(i * 11 % 900)]))
        .collect();
    let frame = annexb(&hn);
    for mtu in [20, 300, 1200] {
        assert_eq!(
            roundtrip(CodecKind::H265, mtu, &frame),
            Some(expected_output(CodecKind::H265, &frame))
        );
    }
    let mut tu = vec![0x12, 0x00, 0x0a, 0x03, 1, 2, 3];
    for i in 0..100usize {
        let pl = r.bytes(i * 37 % 1000);
        let ext = ((i % 3) << 3) as u8;
        tu.extend(cat(&[&[0x36, ext], &leb(pl.len()), &pl]));
        if i % 10 == 0 {
            tu.extend([0x42, 0x00]); // tile list, dropped
        }
    }
    for mtu in [9, 100, 1200] {
        assert_eq!(
            roundtrip(CodecKind::Av1, mtu, &tu),
            Some(expected_output(CodecKind::Av1, &tu))
        );
    }
}

#[test]
fn audio_is_never_split() {
    let mut p = packetizer(CodecKind::Opus);
    assert_eq!(p.packetize(10, &[1; 50]), vec![(vec![1; 50], false)]);
    assert!(p.packetize(10, &[]).is_empty());
    assert!(
        CodecKind::Opus.is_audio() && !CodecKind::Vp8.is_audio() && !CodecKind::Other.is_audio()
    );
}

// ---- frame assembler ----

fn t(ms: u64) -> Instant {
    static BASE: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    *BASE.get_or_init(Instant::now) + Duration::from_millis(ms)
}

/// VP8 frames packetized at `mtu`; returns (packets per frame).
fn vp8_frames(n: usize, mtu: usize, size: usize) -> Vec<Vec<(Vec<u8>, bool)>> {
    let mut p = Vp8Packetizer::new(1);
    (0..n)
        .map(|i| {
            let mut f = vec![if i == 0 { 0x10 } else { 0x11 }];
            f.extend(vec![i as u8; size]);
            p.packetize(mtu, &f)
        })
        .collect()
}

/// Flattens frames into (seq, ts, marker, payload).
fn flatten(
    frames: &[Vec<(Vec<u8>, bool)>],
    seq0: u64,
    ts0: u32,
    step: u32,
) -> Vec<(u64, u32, bool, Vec<u8>)> {
    let mut out = Vec::new();
    let mut seq = seq0;
    for (i, f) in frames.iter().enumerate() {
        for (p, m) in f {
            out.push((
                seq,
                ts0.wrapping_add(step.wrapping_mul(i as u32)),
                *m,
                p.clone(),
            ));
            seq += 1;
        }
    }
    out
}

fn drain(a: &mut FrameAssembler) -> Vec<Frame> {
    std::iter::from_fn(|| a.pop()).collect()
}

#[test]
fn assembler_in_order_and_reordered() {
    let frames = vp8_frames(5, 50, 120);
    let pkts = flatten(&frames, 10, 1000, 3000);
    let mut a = FrameAssembler::new(CodecKind::Vp8, 30);
    // Reverse order within each pair of packets.
    let mut order: Vec<usize> = (0..pkts.len()).collect();
    for c in order.chunks_mut(2) {
        c.reverse();
    }
    let mut got = Vec::new();
    for (k, &i) in order.iter().enumerate() {
        let (s, ts, m, p) = &pkts[i];
        a.push(*s, *ts, *m, p, t(k as u64));
        got.extend(drain(&mut a));
    }
    assert_eq!(got.len(), 5);
    for (i, f) in got.iter().enumerate() {
        assert!(f.contiguous);
        assert_eq!(f.timestamp, 1000 + 3000 * i as u64);
        assert_eq!(f.data[1..], vec![i as u8; 120][..]);
        assert_eq!(f.keyframe, i == 0);
    }
    assert_eq!(got[0].first_seq, 10);
    assert_eq!(a.buffered(), 0);
}

#[test]
fn assembler_emits_as_soon_as_complete() {
    let frames = vp8_frames(2, 50, 60);
    let pkts = flatten(&frames, 0, 0, 3000);
    let mut a = FrameAssembler::new(CodecKind::Vp8, 30);
    // Frame 1 complete before frame 0: nothing until frame 0 completes, then both.
    let n0 = frames[0].len();
    for (s, ts, m, p) in &pkts[n0..] {
        a.push(*s, *ts, *m, p, t(0));
    }
    for (s, ts, m, p) in &pkts[1..n0] {
        a.push(*s, *ts, *m, p, t(0));
    }
    assert!(a.pop().is_none());
    let (s, ts, m, p) = &pkts[0];
    a.push(*s, *ts, *m, p, t(5));
    let got = drain(&mut a);
    assert_eq!(got.len(), 2);
    assert_eq!(got[0].first_arrival, t(0));
}

#[test]
fn assembler_duplicates_and_old_packets_ignored() {
    let frames = vp8_frames(3, 100, 10);
    let pkts = flatten(&frames, 100, 0, 3000);
    let mut a = FrameAssembler::new(CodecKind::Vp8, 30);
    for (s, ts, m, p) in &pkts {
        a.push(*s, *ts, *m, p, t(0));
        a.push(*s, *ts, *m, p, t(1));
    }
    let got = drain(&mut a);
    assert_eq!(got.len(), 3);
    // Re-sending an emitted packet does nothing.
    let (s, ts, m, p) = &pkts[0];
    a.push(*s, *ts, *m, p, t(2));
    assert!(a.pop().is_none());
    assert_eq!(a.buffered(), 0);
}

#[test]
fn assembler_gives_up_on_loss() {
    let frames = vp8_frames(10, 30, 60);
    let per = frames[0].len();
    let pkts = flatten(&frames, 0, 0, 3000);
    let mut a = FrameAssembler::new(CodecKind::Vp8, 5);
    let lost = per + 1; // inside frame 1
    let mut got = Vec::new();
    for (i, (s, ts, m, p)) in pkts.iter().enumerate() {
        if i != lost {
            a.push(*s, *ts, *m, p, t(i as u64));
        }
        got.extend(drain(&mut a));
    }
    // Frame 1 is lost; frame 2 is the next one, not contiguous; the rest contiguous.
    assert_eq!(got.len(), 9);
    assert!(got[0].contiguous && got[0].timestamp == 0);
    assert_eq!(got[1].timestamp, 6000);
    assert!(!got[1].contiguous);
    assert!(got[2..].iter().all(|f| f.contiguous));
    // The lost packet arriving late is ignored.
    let (s, ts, m, p) = &pkts[lost];
    a.push(*s, *ts, *m, p, t(99));
    assert!(a.pop().is_none());
}

#[test]
fn assembler_waits_within_capacity() {
    let frames = vp8_frames(4, 30, 60);
    let pkts = flatten(&frames, 0, 0, 3000);
    let mut a = FrameAssembler::new(CodecKind::Vp8, 100);
    for (s, ts, m, p) in &pkts[1..] {
        a.push(*s, *ts, *m, p, t(0));
    }
    assert!(a.pop().is_none(), "head missing, within capacity: wait");
    let (s, ts, m, p) = &pkts[0];
    a.push(*s, *ts, *m, p, t(0));
    assert_eq!(drain(&mut a).len(), 4);
}

#[test]
fn assembler_timestamp_rollover() {
    let frames = vp8_frames(6, 100, 10);
    let pkts = flatten(&frames, 65_530, u32::MAX - 6000, 3000);
    let mut a = FrameAssembler::new(CodecKind::Vp8, 30);
    for (s, ts, m, p) in &pkts {
        a.push(*s, *ts, *m, p, t(0));
    }
    let got = drain(&mut a);
    let ts: Vec<u64> = got.iter().map(|f| f.timestamp).collect();
    let base = u64::from(u32::MAX - 6000);
    assert_eq!(ts, (0..6).map(|i| base + 3000 * i).collect::<Vec<_>>());
    assert!(ts[3] > u64::from(u32::MAX));
}

#[test]
fn assembler_audio_every_packet_is_a_frame() {
    let mut a = FrameAssembler::new(CodecKind::Opus, 3);
    for s in [5u64, 4, 6, 8, 9, 10, 11, 12] {
        a.push(s, (s * 960) as u32, false, &[s as u8], t(s));
    }
    // 4, 5, 6 come out; 7 is lost and given up once more than 3 packets follow it.
    let got = drain(&mut a);
    let seqs: Vec<u64> = got.iter().map(|f| f.first_seq).collect();
    assert_eq!(seqs, [4, 5, 6, 8, 9, 10, 11, 12]);
    assert!(!got[3].contiguous && got[4].contiguous);
    assert!(got.iter().all(|f| f.keyframe && f.data.len() == 1));
    // Same timestamp on consecutive packets is fine for audio.
    let mut a = FrameAssembler::new(CodecKind::Pcmu, 15);
    a.push(1, 0, false, &[1], t(0));
    a.push(2, 0, false, &[2], t(0));
    assert_eq!(drain(&mut a).len(), 2);
}

#[test]
fn assembler_h264_multi_slice_and_marker_loss() {
    let mut p = H264Packetizer::new();
    let mut r = Rng(3);
    let mut frames = Vec::new();
    for i in 0..4 {
        let first = if i == 0 { 0x65 } else { 0x41 };
        let f = annexb(&[cat(&[&[first], &r.nz(300)]), cat(&[&[first], &r.nz(300)])]);
        frames.push(p.packetize(200, &f));
    }
    let mut pkts = flatten(&frames, 0, 0, 3000);
    // Drop the marker of frame 1's last packet: the timestamp change still ends it.
    let end1 = frames[0].len() + frames[1].len() - 1;
    pkts[end1].2 = false;
    let mut a = FrameAssembler::new(CodecKind::H264, 30);
    for (s, ts, m, p) in &pkts {
        a.push(*s, *ts, *m, p, t(0));
    }
    let got = drain(&mut a);
    assert_eq!(got.len(), 4);
    assert!(got[0].keyframe && !got[1].keyframe);
    assert_eq!(
        got[0]
            .data
            .windows(4)
            .filter(|w| *w == [0, 0, 0, 1])
            .count(),
        2
    );
    // Losing the first packet of frame 2 (FU-A start of slice 1): with capacity 2 the
    // assembler gives up; slice 2's start follows a packet of the same timestamp, so it is
    // known to be mid-frame and frame 2 is skipped; frame 3 comes out not contiguous.
    pkts[end1].2 = true;
    let lost = frames[0].len() + frames[1].len();
    let mut a = FrameAssembler::new(CodecKind::H264, 2);
    let mut got = Vec::new();
    for (i, (s, ts, m, p)) in pkts.iter().enumerate() {
        if i != lost {
            a.push(*s, *ts, *m, p, t(0));
        }
        got.extend(drain(&mut a));
    }
    assert_eq!(got.len(), 3);
    assert!(!got[2].contiguous);
    assert_eq!(got[2].timestamp, 9000);
}

#[test]
fn assembler_joins_mid_frame() {
    let frames = vp8_frames(3, 30, 60);
    let pkts = flatten(&frames, 0, 0, 3000);
    let mut a = FrameAssembler::new(CodecKind::Vp8, 3);
    let mut got = Vec::new();
    for (s, ts, m, p) in &pkts[2..] {
        a.push(*s, *ts, *m, p, t(0));
        got.extend(drain(&mut a));
    }
    assert_eq!(got.len(), 2);
    assert!(!got[0].contiguous);
    assert_eq!(got[0].timestamp, 3000);
}

#[test]
fn assembler_mixed_codecs() {
    let mut audio = FrameAssembler::new(CodecKind::Opus, 15);
    let mut video = FrameAssembler::new(CodecKind::Av1, 30);
    let mut av1 = packetizer(CodecKind::Av1);
    let mut opus = packetizer(CodecKind::Opus);
    let (mut vs, mut as_) = (0u64, 0u64);
    let (mut na, mut nv) = (0, 0);
    for i in 0..20u32 {
        for (p, m) in opus.packetize(1200, &[i as u8; 40]) {
            audio.push(as_, i * 960, m, &p, t(u64::from(i)));
            as_ += 1;
        }
        let tu = av1_temporal_unit(i % 10 == 0, 3000);
        for (p, m) in av1.packetize(1200, &tu) {
            video.push(vs, i * 3000, m, &p, t(u64::from(i)));
            vs += 1;
        }
        for f in drain(&mut audio) {
            assert_eq!(f.data, vec![i as u8; 40]);
            na += 1;
        }
        for f in drain(&mut video) {
            assert_eq!(f.data, expected_output(CodecKind::Av1, &tu));
            assert_eq!(f.keyframe, i % 10 == 0);
            nv += 1;
        }
    }
    assert_eq!((na, nv), (20, 20));
}

#[test]
fn assembler_bounded() {
    // Far-future packets beyond a hole do not grow the buffer beyond the capacity for long.
    let mut a = FrameAssembler::new(CodecKind::Vp8, 10);
    let mut p = Vp8Packetizer::new(0);
    for i in 0..1000u64 {
        let pk = p.packetize(100, &[0x10, 1, 2]);
        a.push(1 + i * 2, (i * 3000) as u32, true, &pk[0].0, t(i));
        while a.pop().is_some() {}
        assert!(a.buffered() <= 11);
    }
    a.push(u64::MAX, 0, true, &[0x10, 1], t(0));
    assert!(a.buffered() <= 11);
}

#[test]
#[ignore = "debug: prints H.265 payloads for diffing against the Go program"]
fn dump_h265() {
    let mut r = Rng(3);
    let mut p = H265Packetizer::new();
    for mtu in [40usize, 100, 576, 1200] {
        let size = |t: usize| if t > mtu - 2 && t <= mtu { mtu - 3 } else { t };
        for k in 0..60usize {
            let vps = cat(&[&[0x40, 0x01], &r.nz(10 + k % 5)]);
            let sps = cat(&[&[0x42, 0x01], &r.nz(20 + k % 9)]);
            let pps = cat(&[&[0x44, 0x01], &r.nz(4 + k % 3)]);
            let idr = cat(&[&[0x26, 0x01], &r.nz(size(mtu - 30 + k * 13) - 2)]);
            let f1 = annexb(&[vps, sps, pps, idr]);
            let mut small = Vec::new();
            for i in 0..=k % 4 {
                small.push(cat(&[
                    &[0x4e, 0x01],
                    &r.nz(size(7 + (k * 7 + i * 11) % 45) - 2),
                ]));
            }
            small.push(cat(&[
                &[0x02, 0x01],
                &r.nz(size((k * 53) % (3 * mtu) + 3) - 2),
            ]));
            let f2 = annexb(&small);
            for f in [f1, f2] {
                for pl in payloads(p.packetize(mtu, &f)) {
                    println!("{mtu} {k} {}", pl.len());
                }
            }
        }
    }
}

#[test]
fn random_streams_never_panic() {
    let mut r = Rng(1234);
    for _ in 0..3000 {
        let n = (r.next() % 400) as usize;
        let mut data = r.bytes(n);
        // Bias towards real headers sometimes.
        if n > 3 && r.next() % 2 == 0 {
            data[2] = 0x90;
        }
        fuzz::rtp_codec(&data);
    }
}

#[test]
fn assembler_skips_sequence_numbers_without_media() {
    // A FEC packet after each frame (ULPFEC in RED takes media sequence numbers): with the
    // numbers skipped, every frame is emitted at once and contiguous.
    let frames = vp8_frames(6, 50, 120);
    let pkts = flatten(&frames, 100, 0, 3000);
    let mut a = FrameAssembler::new(CodecKind::Vp8, 30);
    let mut got = Vec::new();
    let mut shift = 0;
    for (s, ts, m, p) in &pkts {
        a.push(*s + shift, *ts, *m, p, t(0));
        if *m {
            shift += 1;
            // Skipped before or after its neighbours arrive: both work.
            if shift % 2 == 0 {
                a.skip(*s + shift);
                got.extend(drain(&mut a));
            } else {
                got.extend(drain(&mut a));
                a.skip(*s + shift);
            }
        }
        got.extend(drain(&mut a));
    }
    assert_eq!(got.len(), 6);
    assert!(got.iter().all(|f| f.contiguous));
    assert_eq!(a.buffered(), 0);
    // Old and already received numbers are ignored; a real gap still waits.
    a.skip(0);
    let mut b = FrameAssembler::new(CodecKind::Vp8, 30);
    let (s0, ts0, m0, p0) = &pkts[0];
    b.push(*s0, *ts0, *m0, p0, t(0));
    b.skip(*s0);
    assert_eq!(b.buffered(), 1);
}
