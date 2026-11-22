//! Tests of ADR-053: ULPFEC protection levels (the RFC 5109 §10.2 example with erratum 3461,
//! partial and piecewise recovery, the level-0 encoder mode on a lossy link), XR blocks
//! generated from received packets (the RFC 3611 §4.1 examples, pion/rtcp v1.2.20 bytes),
//! complete VoIP metrics, and SDES items (pion/rtcp v1.2.20 bytes, PRIV, RFC 7022).

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::fec::{FecDecoder, FecEncoder, FecHeader, FecScheme, UlpLevel, UlpLevelSpec};
use crate::tests::hex;
use crate::{xr, *};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u32 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (self.0 >> 33) as u32
    }
}

/// An RTP packet with a plain 12-byte header and `len` payload bytes derived from `seq`.
fn rtp(ssrc: u32, seq: u16, ts: u32, pt: u8, marker: bool, len: usize) -> Vec<u8> {
    let mut p = vec![0x80, u8::from(marker) << 7 | pt];
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&ts.to_be_bytes());
    p.extend_from_slice(&ssrc.to_be_bytes());
    p.extend((0..len).map(|i| (i as u8).wrapping_mul(31) ^ seq as u8));
    p
}

fn xor(pkts: &[&Vec<u8>], from: usize, len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    for p in pkts {
        for (i, o) in out.iter_mut().enumerate() {
            *o ^= p.get(12 + from + i).copied().unwrap_or(0);
        }
    }
    out
}

/// RFC 5109 §10.1 / §10.2: packets A..D (SSRC 2, sequence numbers 8..11, timestamps 3, 5, 7,
/// 9, payload types 11 / 18, markers on A and C, 200 / 140 / 100 / 340 bytes).
fn rfc5109_packets() -> Vec<Vec<u8>> {
    [
        (8, 3, 11, true, 200),
        (9, 5, 18, false, 140),
        (10, 7, 11, true, 100),
        (11, 9, 18, false, 340),
    ]
    .into_iter()
    .map(|(seq, ts, pt, m, len)| rtp(2, seq, ts, pt, m, len))
    .collect()
}

/// The two FEC packets of §10.2: #1 level 0 over A, B; #2 level 0 over C, D and level 1 over
/// A..D, L0 = 70, L1 = 90.
fn rfc5109_fec(media: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let refs: Vec<&[u8]> = media.iter().map(Vec::as_slice).collect();
    let l0 = |mask: Vec<usize>| UlpLevelSpec {
        mask,
        protection_len: 70,
    };
    let fec = vec![
        vec![l0(vec![0, 1])],
        vec![
            l0(vec![2, 3]),
            UlpLevelSpec {
                mask: vec![0, 1, 2, 3],
                protection_len: 90,
            },
        ],
    ];
    FecEncoder::new(FecScheme::Ulpfec, 2, 1)
        .encode_ulp(&refs, &fec)
        .unwrap()
}

#[test]
fn ulpfec_rfc5109_two_level_example() {
    let m = rfc5109_packets();
    let fec = rfc5109_fec(&m);
    // Figures 12 / 13 and 15 / 16 / 17. The M recovery bit is computed from the level-0
    // packets as §8.1 says (erratum 3461; the figures show 0): A ^ B and C ^ D are both 1.
    let mut want1 = hex("0099 0008 00000006 0044 0046 c000");
    want1.extend(xor(&[&m[0], &m[1]], 0, 70));
    assert_eq!(fec[0], want1);
    let mut want2 = hex("0099 0008 0000000e 0130 0046 3000");
    want2.extend(xor(&[&m[2], &m[3]], 0, 70));
    want2.extend(hex("005a f000"));
    want2.extend(xor(&[&m[0], &m[1], &m[2], &m[3]], 70, 90));
    assert_eq!(fec[1], want2);

    let h = FecHeader::parse(FecScheme::Ulpfec, &fec[1]).unwrap();
    assert_eq!(
        (h.base_seq, h.offsets.clone(), h.protection_len),
        (8, vec![2, 3], 70)
    );
    assert_eq!(
        h.ulp_levels,
        vec![UlpLevel {
            offsets: vec![0, 1, 2, 3],
            protection_len: 90,
            payload_offset: 14 + 70 + 4,
        }]
    );
    assert_eq!(h.write(FecScheme::Ulpfec), fec[1][..14]);
    assert_eq!(h.write_level(0).unwrap(), hex("005a f000"));
    assert!(h.write_level(1).is_none());

    // Which single losses come back whole: B (140) and C (100) fit in L0 + L1 = 160; A
    // (200) and D (340) only up to 160 bytes.
    for lost in 0..4 {
        let mut dec = FecDecoder::new(FecScheme::Ulpfec, 2);
        let mut got = Vec::new();
        for (i, p) in m.iter().enumerate() {
            if i != lost {
                got.extend(dec.on_media(p));
            }
        }
        for f in &fec {
            got.extend(dec.on_fec(f));
        }
        if m[lost].len() - 12 <= 160 {
            assert_eq!(got, vec![m[lost].clone()], "lost {lost}");
            assert_eq!(dec.partially_recovered(), 0);
        } else {
            assert!(got.is_empty(), "lost {lost}");
            assert_eq!(dec.partially_recovered(), 1);
        }
    }
    // B, with level 1 arriving first: the middle of B is rebuilt before its header is known,
    // then FEC #1 adds the header and the start.
    let mut dec = FecDecoder::new(FecScheme::Ulpfec, 2);
    for i in [0, 2, 3] {
        assert!(dec.on_media(&m[i]).is_empty());
    }
    assert!(dec.on_fec(&fec[1]).is_empty());
    assert_eq!(dec.partially_recovered(), 1);
    assert_eq!(dec.on_fec(&fec[0]), vec![m[1].clone()]);
    assert_eq!(dec.recovered(), 1);
    // A and C lost: both starts come back, level 1 cannot fill two tails.
    let mut dec = FecDecoder::new(FecScheme::Ulpfec, 2);
    dec.on_media(&m[1]);
    dec.on_media(&m[3]);
    assert!(dec.on_fec(&fec[0]).is_empty());
    assert!(dec.on_fec(&fec[1]).is_empty());
    assert_eq!(dec.partially_recovered(), 2);
    // ...until C arrives after all: then A's level 1 range is rebuilt too (A stays partial
    // past 160 bytes), and C's late copy is not returned.
    assert!(dec.on_media(&m[2]).is_empty());
    assert_eq!(dec.partially_recovered(), 1);
}

#[test]
fn ulpfec_level_rules_and_parsing() {
    let m = rfc5109_packets();
    let refs: Vec<&[u8]> = m.iter().map(Vec::as_slice).collect();
    let enc = FecEncoder::new(FecScheme::Ulpfec, 2, 1);
    let lvl = |mask: Vec<usize>, protection_len| UlpLevelSpec {
        mask,
        protection_len,
    };
    // (a) twice at level 1; twice at level 0 with different lengths; (b) at level 1 only.
    for fec in [
        vec![
            vec![lvl(vec![0, 1], 10), lvl(vec![0], 5)],
            vec![lvl(vec![2, 3], 10), lvl(vec![0], 5)],
        ],
        vec![vec![lvl(vec![0, 1], 10)], vec![lvl(vec![1, 2], 12)]],
        vec![vec![lvl(vec![0, 1], 10), lvl(vec![2], 5)]],
        vec![vec![lvl(vec![], 10)]],
        vec![vec![lvl(vec![4], 10)]],
        vec![vec![lvl(vec![0], 0x8000), lvl(vec![0], 0x8000)]],
        vec![vec![]],
    ] {
        assert!(enc.encode_ulp(&refs, &fec).is_none(), "{fec:?}");
    }
    // Twice at level 0 with the same length is allowed.
    let ok = vec![vec![lvl(vec![0, 1], 10)], vec![lvl(vec![1, 2], 10)]];
    assert_eq!(enc.encode_ulp(&refs, &ok).unwrap().len(), 2);
    assert!(
        FecEncoder::new(FecScheme::Flexfec, 2, 1)
            .encode_ulp(&refs, &ok)
            .is_none()
    );

    // Long masks: an offset above 15 at level 1 only sets L for every level.
    let far: Vec<Vec<u8>> = (0..20u16)
        .map(|i| rtp(2, 1000 + i, 0, 96, false, 30))
        .collect();
    let refs: Vec<&[u8]> = far.iter().map(Vec::as_slice).collect();
    let fec = enc
        .encode_ulp(
            &refs,
            &[vec![lvl((0..20).collect(), 8), lvl(vec![1, 19], 22)]],
        )
        .unwrap();
    let f = &fec[0];
    assert_eq!(f[0] & 0x40, 0x40);
    let h = FecHeader::parse(FecScheme::Ulpfec, f).unwrap();
    assert_eq!(h.header_len, 18);
    assert_eq!(h.ulp_levels[0].offsets, vec![1, 19]);
    assert_eq!(h.ulp_levels[0].payload_offset, 18 + 8 + 8);
    assert_eq!(f.len(), 18 + 8 + 8 + 22);
    // Truncated level header, payload past the end, empty mask: rejected.
    assert!(FecHeader::parse(FecScheme::Ulpfec, &f[..18 + 8 + 5]).is_none());
    assert!(FecHeader::parse(FecScheme::Ulpfec, &f[..f.len() - 1]).is_none());
    let mut g = f.clone();
    g[18 + 8 + 2..18 + 8 + 8].fill(0);
    assert!(FecHeader::parse(FecScheme::Ulpfec, &g).is_none());
    // A level-0 protection length longer than the payload: no levels, as before.
    let short = hex("0012abcd 12345678 abcd1122 3344 00000000");
    assert!(
        FecHeader::parse(FecScheme::Ulpfec, &short)
            .unwrap()
            .ulp_levels
            .is_empty()
    );
}

/// The level-0 mode on a lossy link: frames of 2..=12 packets of 60..1200 bytes, 25 %
/// protection, 10 % random loss of media and FEC (a group's FEC is lost as a whole). Every
/// returned packet is the original; every group that lost one media packet (and not its
/// FEC) gets it back whole; the repair bytes are under whole-packet protection's.
#[test]
fn ulpfec_level0_mode_lossy_link() {
    let ssrc = 0x55;
    let mut rng = Rng(7);
    for l0 in [0usize, 40, 100] {
        let mut enc = FecEncoder::new(FecScheme::Ulpfec, ssrc, 64);
        enc.set_ulp_level0(Some(l0));
        let mut full = FecEncoder::new(FecScheme::Ulpfec, ssrc, 64);
        let mut dec = FecDecoder::new(FecScheme::Ulpfec, ssrc);
        let mut originals = HashMap::new();
        let (mut bytes, mut full_bytes, mut singles, mut back) = (0, 0, 0, 0);
        let mut seq = 65_000u16;
        for frame in 0..400u32 {
            let k = 2 + rng.next() as usize % 11;
            let mut group = Vec::new();
            let mut fec = Vec::new();
            for i in 0..k {
                let len = 60 + rng.next() as usize % 1140;
                let p = rtp(ssrc, seq, frame * 3000, 96, i + 1 == k, len);
                seq = seq.wrapping_add(1);
                originals.insert(be(&p), p.clone());
                fec.extend(enc.push(&p, i + 1 == k));
                full_bytes += full
                    .push(&p, i + 1 == k)
                    .iter()
                    .map(Vec::len)
                    .sum::<usize>();
                group.push(p);
            }
            bytes += fec.iter().map(Vec::len).sum::<usize>();
            let media_lost: Vec<bool> = (0..k).map(|_| rng.next() % 10 == 0).collect();
            let fec_lost = fec.iter().any(|_| rng.next() % 10 == 0);
            let mut got = Vec::new();
            for (p, &l) in group.iter().zip(&media_lost) {
                if !l {
                    got.extend(dec.on_media(p));
                }
            }
            if !fec_lost {
                for f in &fec {
                    got.extend(dec.on_fec(f));
                }
            }
            let n = media_lost.iter().filter(|&&l| l).count();
            back += got.len();
            for r in &got {
                assert_eq!(Some(r), originals.get(&be(r)), "l0 {l0}");
            }
            if n == 1 && !fec_lost {
                singles += 1;
                assert_eq!(got.len(), 1, "l0 {l0} frame {frame}");
            }
        }
        assert!(
            singles > 50 && back >= singles,
            "l0 {l0}: {back}, {singles}"
        );
        assert!(bytes < full_bytes, "l0 {l0}: {bytes} vs {full_bytes}");
    }
}

fn be(p: &[u8]) -> u16 {
    u16::from_be_bytes([p[2], p[3]])
}

// --- XR blocks from received packets ---

/// pion/rtcp v1.2.20 `ExtendedReport` with loss RLE (T 0 and 2), duplicate RLE (wrapping)
/// and receipt times blocks (even chunk counts: pion leaves out the null chunk of odd ones).
const PION_XR: &str = "80cf0014deadbeef010000040102030435fd362a4015afff4009c000010200030102030435fd362afde00003\
0200000301020304fffa000afbff400103010005010203040064006a00015f900001615200016698";

#[test]
fn xr_rle_pion_bytes() {
    let rle = |t, begin, end, chunks: &[u16]| RleReport {
        ssrc: 0x0102_0304,
        thinning: t,
        begin_seq: begin,
        end_seq: end,
        chunks: chunks.to_vec(),
    };
    let xr = Rtcp::ExtendedReport {
        ssrc: 0xdead_beef,
        blocks: vec![
            XrBlock::LossRle(rle(0, 13821, 13866, &[0x4015, 0xafff, 0x4009, 0xc000])),
            XrBlock::LossRle(rle(2, 13821, 13866, &[0xfde0, 3])),
            XrBlock::DuplicateRle(rle(0, 65530, 10, &[0xfbff, 0x4001])),
            XrBlock::PacketReceiptTimes {
                ssrc: 0x0102_0304,
                thinning: 1,
                begin_seq: 100,
                end_seq: 106,
                times: vec![90000, 90450, 91800],
            },
        ],
    };
    let w = write_compound(std::slice::from_ref(&xr));
    assert_eq!(w, hex(PION_XR));
    assert_eq!(parse_compound(&w).unwrap(), vec![xr]);
}

/// Feeds `seqs` 1 ms apart from `start` (RTP clock 8 kHz, timestamps 160 per packet).
fn log_of(seqs: impl IntoIterator<Item = u16>, start: Instant) -> ReceiptLog {
    let mut log = ReceiptLog::new(7, 8000, 4096);
    for (i, s) in seqs.into_iter().enumerate() {
        log.on_packet(
            start + Duration::from_millis(i as u64),
            s,
            u32::from(s) * 160,
        );
    }
    log
}

#[test]
fn xr_rle_rfc3611_examples() {
    let t0 = Instant::now();
    // §4.1: 45 packets from 13821, the 22nd and 24th lost.
    let log = log_of((13821..=13865).filter(|&s| s != 13842 && s != 13844), t0);
    let Some(XrBlock::LossRle(r)) = log.loss_rle(0) else {
        panic!()
    };
    assert_eq!((r.begin_seq, r.end_seq), (13821, 13866));
    // Run of 21 receipts, bit vector 0101 1111 1111 111, run of 9 receipts.
    assert_eq!(r.chunks, [0x4015, 0xafff, 0x4009]);
    // Written with the terminating null chunk.
    let mut w = Vec::new();
    xr::write_blocks(&[XrBlock::LossRle(r.clone())], &mut w);
    assert_eq!(w, hex("01000004 00000007 35fd362a 4015afff 40090000"));
    let decoded = r.decode();
    assert_eq!(decoded.len(), 45);
    assert!(
        decoded
            .iter()
            .all(|&(s, v)| v == (s != 13842 && s != 13844))
    );
    // With the 44th (13864) lost as well, T = 2 reports 13824, 13828, ..., 13864: bit
    // vector 1111 1011 1100 000 (13842 is not reported).
    let log = log_of(
        (13821..=13865).filter(|&s| s != 13842 && s != 13844 && s != 13864),
        t0,
    );
    let Some(XrBlock::LossRle(r2)) = log.loss_rle(2) else {
        panic!()
    };
    assert_eq!(r2.chunks, [0xfde0]);
    assert_eq!(
        r2.reported_seqs().collect::<Vec<_>>()[..3],
        [13824, 13828, 13832]
    );
    assert_eq!(r2.decode().len(), 11);
    // The 44th lost as well: run of 21, the same bit vector, 1111 1110 1000 000.
    let mut trace = vec![true; 45];
    for i in [21, 23, 43] {
        trace[i] = false;
    }
    assert_eq!(RleReport::encode(&trace), [0x4015, 0xafff, 0xff40]);
    // No duplicates: one run of "no duplicate".
    let Some(XrBlock::DuplicateRle(d)) = log.duplicate_rle(0) else {
        panic!()
    };
    assert_eq!(d.chunks, [0x4000 | 45]);
}

#[test]
fn rle_encode_decode_round_trips() {
    let mut rng = Rng(3);
    for case in 0..300 {
        let t = (rng.next() % 4) as u8;
        // At most 65533 sequence numbers spanned.
        let n = rng.next() as usize % ((65_533 >> t) - 1);
        let p = 1 + rng.next() % 40;
        let mut v = true;
        let trace: Vec<bool> = (0..n)
            .map(|_| {
                if rng.next() % 100 < p {
                    v = !v;
                }
                v
            })
            .collect();
        let begin = rng.next() as u16;
        // A span with exactly `n` reported sequence numbers.
        let first = (u32::from(begin) + (1 << t) - 1) >> t << t;
        let end = (first + (n as u32) * (1 << t)) as u16;
        let r = RleReport {
            ssrc: 1,
            thinning: t,
            begin_seq: begin,
            end_seq: if n == 0 { begin } else { end },
            chunks: RleReport::encode(&trace),
        };
        let d = r.decode();
        assert_eq!(
            d.iter().map(|x| x.1).collect::<Vec<_>>(),
            trace,
            "case {case}"
        );
        assert!(
            d.iter()
                .enumerate()
                .all(|(i, &(s, _))| s == (first as u16).wrapping_add((i as u16) << t))
        );
        // Chunks never exceed what the trace needs: a run chunk only for runs of 15+ or
        // the tail.
        assert!(r.chunks.len() <= n / 15 + 2, "case {case}");
    }
}

#[test]
fn receipt_log_blocks() {
    let t0 = Instant::now();
    let mut log = ReceiptLog::new(9, 90_000, 4096);
    // 65533, 65534, 65535, 0 (dup), 2, 3 — 1 is lost; 65534 comes twice. 10 ms apart.
    let arrivals = [65533u16, 65534, 65535, 0, 65534, 2, 0, 3];
    for (i, &s) in arrivals.iter().enumerate() {
        log.on_packet(
            t0 + Duration::from_millis(10 * i as u64),
            s,
            1000 + u32::from(s),
        );
    }
    assert_eq!(log.len(), 7);
    let Some(XrBlock::LossRle(l)) = log.loss_rle(0) else {
        panic!()
    };
    assert_eq!((l.begin_seq, l.end_seq), (65533, 4));
    assert_eq!(
        l.decode(),
        [
            (65533, true),
            (65534, true),
            (65535, true),
            (0, true),
            (1, false),
            (2, true),
            (3, true)
        ]
    );
    let Some(XrBlock::DuplicateRle(d)) = log.duplicate_rle(0) else {
        panic!()
    };
    // Zero marks a duplicate (65534 and 0); a loss is a one.
    assert_eq!(
        d.decode().iter().map(|x| x.1).collect::<Vec<_>>(),
        [true, false, true, false, true, true, true]
    );
    // Receipt times: two blocks around the loss; anchored at the first packet's timestamp
    // (1000 + 65533), 900 ticks per 10 ms, the first copy's time for duplicates.
    let t = log.receipt_times(0);
    let base = 1000 + 65533u32;
    assert_eq!(
        t,
        vec![
            XrBlock::PacketReceiptTimes {
                ssrc: 9,
                thinning: 0,
                begin_seq: 65533,
                end_seq: 1,
                times: vec![base, base + 900, base + 1800, base + 2700],
            },
            XrBlock::PacketReceiptTimes {
                ssrc: 9,
                thinning: 0,
                begin_seq: 2,
                end_seq: 4,
                times: vec![base + 4500, base + 6300],
            },
        ]
    );
    // Thinning 1: 65534, 0, 2 are reported (1 is not, so the run goes on).
    let t1 = log.receipt_times(1);
    assert_eq!(t1.len(), 1);
    let XrBlock::PacketReceiptTimes {
        begin_seq,
        end_seq,
        times,
        ..
    } = &t1[0]
    else {
        panic!()
    };
    assert_eq!((*begin_seq, *end_seq, times.len()), (65534, 3, 3));
    // Every block writes and parses back.
    let mut blocks = vec![XrBlock::LossRle(l), XrBlock::DuplicateRle(d)];
    blocks.extend(t);
    let xr = Rtcp::ExtendedReport { ssrc: 1, blocks };
    assert_eq!(
        parse_compound(&write_compound(std::slice::from_ref(&xr))).unwrap(),
        vec![xr]
    );

    // The next interval starts after 3; older packets are ignored.
    log.next_interval();
    assert!(log.is_empty() && log.loss_rle(0).is_none() && log.receipt_times(0).is_empty());
    log.on_packet(t0, 2, 0);
    assert!(log.is_empty());
    log.on_packet(t0, 6, 0);
    let Some(XrBlock::LossRle(l)) = log.loss_rle(0) else {
        panic!()
    };
    assert_eq!((l.begin_seq, l.end_seq), (4, 7));
    assert_eq!(l.chunks, [0x8000 | 0x1000]);
}

#[test]
fn receipt_log_capacity_and_unwrap() {
    let t0 = Instant::now();
    let mut log = ReceiptLog::new(1, 8000, 100);
    for s in 0..250u16 {
        log.on_packet(t0, s, 0);
    }
    let Some(XrBlock::LossRle(l)) = log.loss_rle(0) else {
        panic!()
    };
    assert_eq!(
        (l.begin_seq, l.end_seq, l.chunks),
        (150, 250, vec![0x4000 | 100])
    );
    // A jump of exactly 32768 stays in the cycle (no rollover): from 100 forward.
    let mut log = ReceiptLog::new(1, 8000, 65_533);
    log.on_packet(t0, 100, 0);
    log.on_packet(t0, 100 + 0x8000, 0);
    assert_eq!(log.len(), 0x8001);
    // From 40000 the same distance is backwards (forward would roll over): before the
    // interval, so ignored.
    let mut log = ReceiptLog::new(1, 8000, 65_533);
    log.on_packet(t0, 40000, 0);
    log.on_packet(t0, 40000 - 0x8000, 0);
    assert_eq!(log.len(), 1);
    // The capacity is at most what one block may span.
    let mut log = ReceiptLog::new(1, 1, 1 << 20);
    for s in 0..70_000u32 {
        log.on_packet(t0, s as u16, 0);
    }
    assert_eq!(log.len(), MAX_XR_SPAN);
}

#[test]
fn recv_stream_receipt_blocks() {
    let t0 = Instant::now();
    let mut rx = RecvStream::new(5, 90_000, false);
    assert!(rx.receipt_blocks(0, true, true, true).is_empty());
    rx.enable_receipt_log(1000);
    for s in [10u16, 11, 13, 13, 14] {
        rx.receive(t0, s, 0);
    }
    // FEC-rebuilt packets stay lost in the log, as in receiver reports.
    rx.receive_recovered(t0, 12);
    let b = rx.receipt_blocks(0, true, true, true);
    assert_eq!(b.len(), 4);
    let XrBlock::LossRle(l) = &b[0] else { panic!() };
    assert_eq!(l.decode().iter().filter(|x| !x.1).count(), 1);
    let XrBlock::DuplicateRle(d) = &b[1] else {
        panic!()
    };
    assert_eq!(d.decode()[3], (13, false));
    assert!(matches!(
        b[2],
        XrBlock::PacketReceiptTimes {
            begin_seq: 10,
            end_seq: 12,
            ..
        }
    ));
    assert!(matches!(
        b[3],
        XrBlock::PacketReceiptTimes {
            begin_seq: 13,
            end_seq: 15,
            ..
        }
    ));
    // The interval ended.
    assert!(rx.receipt_blocks(0, true, true, true).is_empty());
    rx.receive(t0, 15, 0);
    assert_eq!(rx.receipt_blocks(0, true, false, false).len(), 1);
    assert_eq!(rx.receipt_log().map(ReceiptLog::ssrc), Some(5));
}

// --- VoIP metrics ---

#[test]
fn voip_report_fields() {
    let mut m = BurstLossModel::new(16);
    for i in 0..200 {
        m.on_packet(i % 50 == 7, i == 100);
    }
    let q = VoipQuality {
        round_trip: Some(Duration::from_micros(123_600)),
        end_system_delay: Some(Duration::from_millis(80)),
        signal_level: Some(-18),
        noise_level: Some(-60),
        rerl: Some(45),
        r_factor: Some(93),
        ext_r_factor: Some(101),
        mos_lq: Some(42),
        mos_cq: Some(9),
        plc: Plc::Enhanced,
        jitter_buffer: Some(JitterBufferConfig {
            adaptive: true,
            rate: 5,
            nominal: Duration::from_millis(40),
            maximum: Duration::from_millis(120),
            abs_max: Duration::from_secs(100),
        }),
    };
    let v = m.report(0xabc, 20, &q);
    let base = m.metrics(0xabc, 20);
    assert_eq!(
        (v.loss_rate, v.discard_rate, v.burst_density, v.gap_density),
        (
            base.loss_rate,
            base.discard_rate,
            base.burst_density,
            base.gap_density
        )
    );
    assert_eq!(
        (v.burst_duration, v.gap_duration, v.gmin),
        (base.burst_duration, base.gap_duration, 16)
    );
    assert_eq!((v.round_trip_delay, v.end_system_delay), (123, 80));
    assert_eq!((v.signal_level, v.noise_level, v.rerl), (0xee, 0xc4, 45));
    // Out of range: unavailable.
    assert_eq!(
        (v.r_factor, v.ext_r_factor, v.mos_lq, v.mos_cq),
        (93, 127, 42, 127)
    );
    assert_eq!(v.rx_config, 0b1011_0101);
    assert_eq!((v.jb_nominal, v.jb_maximum, v.jb_abs_max), (40, 120, 65535));
    // Nothing known: unavailable / zero / unknown.
    let u = m.report(1, 20, &VoipQuality::default());
    assert_eq!(
        (
            u.round_trip_delay,
            u.end_system_delay,
            u.signal_level,
            u.rerl,
            u.r_factor,
            u.mos_cq
        ),
        (0, 0, 127, 127, 127, 127)
    );
    assert_eq!((u.rx_config, u.jb_nominal), (0, 0));
    let w = write_compound(&[Rtcp::ExtendedReport {
        ssrc: 1,
        blocks: vec![XrBlock::VoipMetrics(v)],
    }]);
    let Ok(p) = parse_compound(&w) else { panic!() };
    assert_eq!(
        p,
        vec![Rtcp::ExtendedReport {
            ssrc: 1,
            blocks: vec![XrBlock::VoipMetrics(v)]
        }]
    );
}

#[test]
fn pcm_levels() {
    let sine = |amp: f64| -> Vec<i16> {
        (0..8000)
            .map(|i| {
                (amp * (f64::from(i) * 2.0 * std::f64::consts::PI * 1000.0 / 8000.0).sin()) as i16
            })
            .collect()
    };
    assert_eq!(pcm_level_dbm0(&sine(32767.0)), Some(3));
    // 20 dB down: -16.86 dBm0.
    assert_eq!(pcm_level_dbm0(&sine(3276.7)), Some(-17));
    assert_eq!(pcm_level_dbm0(&sine(32.767)), Some(-57));
    assert_eq!(pcm_level_dbm0(&[0; 160]), Some(-127));
    assert_eq!(pcm_level_dbm0(&[]), None);
    assert_eq!(pcm_level_dbm0(&[i16::MIN; 10]), Some(3));
}

// --- SDES ---

/// pion/rtcp v1.2.20 `SourceDescription`: CNAME and PRIV ("video" / "front-cam"), then MID,
/// RtpStreamId and an empty PRIV (prefix length 0).
const PION_SDES: &str = "82ca000d1122334401097573657240686f7374080f05766964656f66726f6e742d63616d0000\
0000556677880f01300c0268690801000000";

#[test]
fn sdes_items_pion_bytes() {
    let chunks = vec![
        (
            0x1122_3344,
            vec![
                SdesItem::cname("user@host"),
                SdesItem::private("video", "front-cam"),
            ],
        ),
        (
            0x5566_7788,
            vec![
                SdesItem::text(SdesItem::MID, "0"),
                SdesItem::text(SdesItem::RTP_STREAM_ID, "hi"),
                SdesItem::private("", ""),
            ],
        ),
    ];
    let pkt = Rtcp::SourceDescription(
        chunks
            .iter()
            .map(|(s, items)| (*s, items.iter().map(SdesItem::to_pair).collect()))
            .collect(),
    );
    let w = write_compound(std::slice::from_ref(&pkt));
    assert_eq!(w, hex(PION_SDES));
    let Ok(p) = parse_compound(&w) else { panic!() };
    assert_eq!(p, vec![pkt]);
    let Rtcp::SourceDescription(c) = &p[0] else {
        panic!()
    };
    let typed: Vec<(u32, Vec<SdesItem>)> = c
        .iter()
        .map(|(s, items)| {
            (
                *s,
                items
                    .iter()
                    .map(|(t, v)| SdesItem::from_pair(*t, v))
                    .collect(),
            )
        })
        .collect();
    assert_eq!(typed, chunks);
    assert_eq!(typed[0].1[1].item_type(), SdesItem::PRIV);
}

#[test]
fn sdes_priv_edges() {
    // A 200-octet prefix (length octet above 127) survives the wire.
    let long = SdesItem::private("p".repeat(200), "v".repeat(20));
    let pkt = Rtcp::SourceDescription(vec![(1, vec![long.to_pair()])]);
    let w = write_compound(std::slice::from_ref(&pkt));
    assert_eq!(&w[8..11], &[8, 221, 200]);
    let Ok(p) = parse_compound(&w) else { panic!() };
    assert_eq!(p, vec![pkt]);
    let Rtcp::SourceDescription(c) = &p[0] else {
        panic!()
    };
    assert_eq!(SdesItem::from_pair(c[0].1[0].0, &c[0].1[0].1), long);
    // Too long: the value is cut (at a character boundary) to 254 octets in all.
    let big = SdesItem::private("x", "é".repeat(200));
    let (t, s) = big.to_pair();
    let SdesItem::Priv { prefix, value } = SdesItem::from_pair(t, &s) else {
        panic!()
    };
    assert_eq!((prefix.as_str(), value.len()), ("x", 252));
    // A prefix length past the text, or no text: a plain type-8 text item.
    assert_eq!(
        SdesItem::from_pair(8, "\u{9}abc"),
        SdesItem::text(8, "\u{9}abc")
    );
    assert_eq!(SdesItem::from_pair(8, ""), SdesItem::text(8, ""));
    // Text items are cut at a character boundary too, and the chunk stays aligned.
    let pkt = Rtcp::SourceDescription(vec![(1, vec![(SdesItem::NOTE, "ü".repeat(200))])]);
    let w = write_compound(&[pkt]);
    assert_eq!(w[9], 254);
    assert_eq!(w.len() % 4, 0);
    let Ok(p) = parse_compound(&w) else { panic!() };
    let Rtcp::SourceDescription(c) = &p[0] else {
        panic!()
    };
    assert_eq!(c[0].1[0].1, "ü".repeat(127));
}

#[test]
fn rfc7022_cname() {
    assert_eq!(random_cname(&[0; 12]), "AAAAAAAAAAAAAAAA");
    assert_eq!(
        random_cname(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]),
        "AAECAwQFBgcICQoL"
    );
    assert_eq!(random_cname(&[0xff; 12]), "////////////////");
}

// --- fuzz seeds ---

/// `rtp_rtcp` seeds: the pion XR and SDES packets, the RFC 3611 §4.1 loss RLE, a complete
/// VoIP metrics block, a 200-octet PRIV prefix, and an RTP packet whose payload drives the
/// receipt log.
pub(crate) fn seeds() -> Vec<Vec<u8>> {
    let t0 = Instant::now();
    let log = log_of((13821..=13865).filter(|&s| s != 13842 && s != 13844), t0);
    let mut blocks: Vec<XrBlock> = log.loss_rle(0).into_iter().collect();
    blocks.extend(log.duplicate_rle(1));
    blocks.extend(log.receipt_times(3));
    let mut m = BurstLossModel::new(16);
    (0..100).for_each(|i| m.on_packet(i % 9 == 0, false));
    blocks.push(XrBlock::VoipMetrics(m.report(
        3,
        20,
        &VoipQuality {
            round_trip: Some(Duration::from_millis(50)),
            r_factor: Some(90),
            mos_lq: Some(41),
            ..VoipQuality::default()
        },
    )));
    let xr = write_compound(&[Rtcp::ExtendedReport { ssrc: 1, blocks }]);
    let sdes = write_compound(&[Rtcp::SourceDescription(vec![(
        1,
        vec![
            SdesItem::private("p".repeat(200), "v").to_pair(),
            SdesItem::text(SdesItem::APSI, "app").to_pair(),
        ],
    )])]);
    let mut pkt = rtp(9, 100, 0, 40, false, 0);
    pkt.extend_from_slice(&[3, 0, 0, 1, 0, 10, 0, 2, 20, 0, 1, 1, 0x80, 0, 5]);
    vec![hex(PION_XR), hex(PION_SDES), xr, sdes, pkt]
}

/// `rtp_fec` seeds: the RFC 5109 §10.2 two-level FEC packet, and pseudo-packets with the
/// level-0 mode on (selector 0x30: ULPFEC, L0 = 12).
pub(crate) fn fec_seeds() -> Vec<Vec<u8>> {
    let m = rfc5109_packets();
    let fec = rfc5109_fec(&m);
    let mut a = vec![0];
    a.extend_from_slice(&fec[1]);
    let mut b = vec![0x30];
    for (i, p) in m.iter().enumerate() {
        b.push(u8::from(i == 1));
        let body = &p[12..p.len().min(60)];
        b.push(body.len() as u8);
        b.extend_from_slice(body);
    }
    vec![a, b]
}
