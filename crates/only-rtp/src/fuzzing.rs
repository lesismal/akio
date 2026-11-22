//! Fuzz entry points (feature `fuzzing`; not a public API). The `fuzz/` cargo-fuzz project
//! calls them; the unit tests below replay `fuzz/corpus/<target>` on stable.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::fec::{FecDecoder, FecEncoder, FecHeader, FecScheme, UlpLevelSpec, red};
use crate::{
    BurstLossModel, CcfbSender, EModel, EcnFeedback, EcnReceiver, EcnSummary, Extension,
    ExtensionMap, ReceiptLog, RecvStream, RleReport, RrtrResponder, Rtcp, RtpHeader, SdesItem,
    TmmbrHandler, TwccSender, VoipQuality, XrBlock, bounded_bitrate, bounding_set, parse_compound,
    write_compound,
};

fn full_map() -> ExtensionMap {
    let mut m = ExtensionMap::new();
    // Ids 1..=9 (one-byte capable) for every extension, so both forms get exercised by
    // whatever the input uses.
    for (i, e) in Extension::ALL.into_iter().enumerate() {
        m.insert(i as u8 + 1, e);
    }
    m
}

/// `rtp_rtcp`: arbitrary bytes as an RTP packet (every extension mapped) and as a compound
/// RTCP packet. Parsed RTP headers re-write and re-parse to the same header; parsed RTCP
/// (including XR, TMMBR / TMMBN and RFC 8888 feedback) re-writes to bytes that parse, and a
/// second write / parse round is stable. What parsed is fed to a `RecvStream` (with a
/// receipt log, whose RLE / receipt times blocks write, parse and decode back to what was
/// received), a `SendStream`, a `TwccSender`, a `CcfbSender`, an `RrtrResponder` and a
/// `TmmbrHandler` (whose bounding set is a subset of the requests). SDES pairs convert to
/// typed items and back stably; RLE chunks decode, re-encode and decode to the same trace;
/// VoIP metrics built from the input stay in range. RFC 6679 ECN feedback messages and XR
/// ECN summaries convert and write back to themselves, and the feedback of an `EcnReceiver`
/// fed the RTP header's numbers does too. Never panics.
pub fn rtp_rtcp(data: &[u8]) {
    let map = full_map();
    let now = Instant::now();
    if let Some(h) = RtpHeader::parse(data, &map) {
        let payload = h.payload(data).to_vec();
        let out = h.write(&map, &payload);
        let h2 = RtpHeader::parse(&out, &map);
        assert!(h2.is_some(), "rewritten header does not parse");
        if let Some(h2) = h2 {
            assert_eq!(h2.payload(&out), &payload[..]);
            let mut a = h.clone();
            let mut b = h2;
            // Lengths depend on the extension form and unknown extensions.
            a.header_len = 0;
            b.header_len = 0;
            a.csrc.truncate(15);
            assert_eq!(a, b);
        }
        let mut rx = RecvStream::new(h.ssrc, 90_000, true);
        rx.enable_receipt_log(usize::from(h.payload_type) * 8);
        let _ = rx.receive(now, h.sequence_number, h.timestamp);
        let _ = rx.receive(
            now + Duration::from_millis(5),
            h.sequence_number.wrapping_add(3),
            h.timestamp,
        );
        let _ = rx.receive(now, h.sequence_number, h.timestamp);
        let _ = rx.poll_nack(now + Duration::from_millis(50));
        let _ = rx.report_block(now + Duration::from_millis(60));
        let _ = rx.statistics_summary();
        receipt_log(&payload, h.ssrc, now);
        let mut ecn = EcnReceiver::new();
        for (i, b) in payload.iter().take(64).enumerate() {
            let seq = h
                .sequence_number
                .wrapping_add(u16::from(*b))
                .wrapping_sub(128);
            ecn.on_received(h.ssrc ^ (i as u32 & 1), seq, *b >> 6);
        }
        for fb in ecn.feedback(1, true) {
            assert_eq!(EcnFeedback::from_rtcp(&fb.to_rtcp()), Some(fb));
        }
    }
    if let Ok(pkts) = parse_compound(data) {
        let w = write_compound(&pkts);
        let p2 = parse_compound(&w);
        assert!(p2.is_ok(), "rewritten RTCP does not parse");
        if let Ok(p2) = p2 {
            assert_eq!(p2.len(), pkts.len());
            let p3 = parse_compound(&write_compound(&p2)).ok();
            assert!(p3.as_ref() == Some(&p2));
        }
        let mut tx = TwccSender::new();
        let mut stream = crate::SendStream::new(1, 90_000, Some(2), 0);
        let mut ccfb = CcfbSender::new();
        let mut rrtr = RrtrResponder::new();
        let mut tmmbr = TmmbrHandler::new(1);
        let mut rx = RecvStream::new(1, 90_000, true);
        for p in &pkts {
            match p {
                Rtcp::TransportCc(fb) => {
                    for (seq, _) in fb.packets.iter().take(64) {
                        tx.on_sent(*seq, now, 1200);
                    }
                    let _ = tx.on_feedback(now, fb);
                }
                Rtcp::ReceiverReport { reports, .. } | Rtcp::SenderReport { reports, .. } => {
                    for r in reports {
                        stream.handle_report_block(now, 0x1234_5678_9abc_def0, r);
                    }
                }
                Rtcp::Nack { lost, .. } => {
                    let _ = stream.resend(now, lost, Some(97), &map);
                }
                Rtcp::CongestionControl(fb) => {
                    for s in fb.streams.iter().take(4) {
                        for i in 0..s.reports.len().min(64) {
                            ccfb.on_sent(s.ssrc, s.begin_seq.wrapping_add(i as u16), now, 1200);
                        }
                    }
                    let r = ccfb.on_feedback(now, fb);
                    assert!(r.windows(2).all(|w| w[0].seq < w[1].seq));
                }
                Rtcp::SourceDescription(chunks) => {
                    for (t, v) in chunks.iter().flat_map(|(_, items)| items) {
                        let item = SdesItem::from_pair(*t, v);
                        assert_eq!(item.item_type(), *t);
                        let (t2, v2) = item.to_pair();
                        let item2 = SdesItem::from_pair(t2, &v2);
                        assert_eq!(SdesItem::from_pair(t2, &item2.to_pair().1), item2);
                    }
                }
                Rtcp::ExtendedReport { ssrc, blocks } => {
                    for b in blocks {
                        match b {
                            XrBlock::LossRle(r) | XrBlock::DuplicateRle(r) => {
                                let d = r.decode();
                                let trace: Vec<bool> = d.iter().map(|x| x.1).collect();
                                let r2 = RleReport {
                                    chunks: RleReport::encode(&trace),
                                    ..r.clone()
                                };
                                // Chunks may end before the interval: the re-encoded
                                // trace's padding bits then read as losses after it.
                                let d2 = r2.decode();
                                assert!(d2.len() >= d.len());
                                assert_eq!(d2[..d.len()], d[..]);
                                if d.len() == r.reported_seqs().count() {
                                    assert_eq!(d2, d);
                                }
                            }
                            XrBlock::VoipMetrics(v) => {
                                let mut m = BurstLossModel::new(v.gmin);
                                for i in 0..u32::from(v.loss_rate) {
                                    m.on_packet(i % 3 == 0, i % 5 == 0);
                                }
                                let q = VoipQuality {
                                    r_factor: Some(v.r_factor),
                                    mos_lq: Some(v.mos_lq),
                                    signal_level: Some(v.signal_level as i8),
                                    rerl: Some(v.rerl),
                                    ..VoipQuality::default()
                                };
                                let out = m.report(*ssrc, v.burst_duration, &q);
                                assert!(out.r_factor <= 100 || out.r_factor == 127);
                                assert!((10..=50).contains(&out.mos_lq) || out.mos_lq == 127);
                                assert!(out.rerl <= 126);
                                // Decoding is stable through another report.
                                let got = v.quality();
                                assert_eq!(m.report(*ssrc, 20, &got).quality(), got);
                                let rate = Some(u32::from(v.burst_duration) * 64);
                                for (codec, rate) in [
                                    ("opus", None),
                                    ("opus", rate),
                                    ("PCMU", None),
                                    ("g722", rate),
                                    ("G729", None),
                                    ("evs", rate),
                                    ("AMR-WB", rate),
                                ] {
                                    let e = EModel::for_codec_rate(codec, got.plc, rate)
                                        .unwrap_or_default();
                                    let s = e.estimate_report(
                                        &m,
                                        &got,
                                        Duration::from_millis(u64::from(v.gap_duration)),
                                        Duration::from_millis(20),
                                    );
                                    assert!((0.0..=100.0).contains(&s.r_factor));
                                    assert!((1.0..=4.5).contains(&s.mos_cq));
                                    assert!(s.r_factor <= s.r_lq + 1e-9);
                                }
                            }
                            XrBlock::ReceiverReferenceTime { ntp } => {
                                rrtr.on_rrtr(now, *ssrc, *ntp);
                            }
                            XrBlock::Dlrr(items) => {
                                for i in items {
                                    let _ = rx.handle_dlrr(0x1234_5678_9abc_def0, i);
                                }
                            }
                            _ => {
                                if let Some(sums) = EcnSummary::from_xr(b) {
                                    let b2 = EcnSummary::to_xr(&sums);
                                    assert_eq!(EcnSummary::from_xr(&b2).as_ref(), Some(&sums));
                                    for w in sums.windows(2) {
                                        let _ = w[1].counters.since(&w[0].counters);
                                    }
                                }
                            }
                        }
                    }
                    let _ = rrtr.dlrr(now + Duration::from_millis(5));
                }
                Rtcp::Tmmbr {
                    sender_ssrc,
                    entries,
                } => {
                    let _ = tmmbr.on_tmmbr(now, *sender_ssrc, entries);
                    let _ = tmmbr.max_bitrate(now, 100.0);
                    let _ = write_compound(&[tmmbr.tmmbn(now)]);
                }
                Rtcp::Unknown { .. } => {
                    if let Some(fb) = EcnFeedback::from_rtcp(p) {
                        let w = write_compound(&[fb.to_rtcp()]);
                        let back = parse_compound(&w).expect("ECN feedback parses");
                        assert_eq!(EcnFeedback::from_rtcp(&back[0]), Some(fb));
                    }
                }
                Rtcp::Tmmbn { entries, .. } => {
                    let set = bounding_set(entries);
                    assert!(set.iter().all(|t| entries.contains(t)));
                    assert_eq!(set.is_empty(), entries.iter().all(|t| t.bitrate == 0));
                    let _ = bounded_bitrate(&set, 50.0);
                }
                _ => {}
            }
        }
    }
}

/// Packets from `data` (two bytes of sequence number delta, one of arrival delta each) fed
/// to a receipt log: its blocks write and parse back, and the loss RLE reports exactly
/// what was received.
fn receipt_log(data: &[u8], ssrc: u32, now: Instant) {
    let mut log = ReceiptLog::new(
        ssrc,
        8000,
        1 + usize::from(data.first().copied().unwrap_or(0)) * 64,
    );
    let mut seq = 0u16;
    let mut t = now;
    let mut got = std::collections::HashSet::new();
    for c in data.chunks_exact(3) {
        seq = seq.wrapping_add(u16::from_be_bytes([c[0], c[1]]) % 70);
        t += Duration::from_millis(u64::from(c[2]));
        log.on_packet(t, seq, u32::from(c[2]));
        got.insert(seq);
    }
    for thinning in [0, 2] {
        let mut blocks: Vec<XrBlock> = log.loss_rle(thinning).into_iter().collect();
        if let Some(XrBlock::LossRle(r)) = blocks.first() {
            for (s, v) in r.decode() {
                assert!(!v || got.contains(&s), "reported received {s}");
            }
        }
        blocks.extend(log.duplicate_rle(thinning));
        blocks.extend(log.receipt_times(thinning));
        let xr = Rtcp::ExtendedReport { ssrc, blocks };
        let w = write_compound(std::slice::from_ref(&xr));
        assert_eq!(parse_compound(&w).ok(), Some(vec![xr]));
    }
    log.next_interval();
    assert!(log.loss_rle(0).is_none());
}

/// The FEC scheme selected by a fuzz input's first byte.
fn scheme(b: u8) -> FecScheme {
    match b % 3 {
        0 => FecScheme::Ulpfec,
        1 => FecScheme::Flexfec03,
        _ => FecScheme::Flexfec,
    }
}

/// `rtp_fec`: the first byte picks the FEC scheme; the rest is parsed as a FEC header
/// (whose re-written form parses to the same fields), as a RED payload (written back to the
/// same blocks), as an RTP packet to RED-wrap and unwrap, and as `[kind][len][bytes]`
/// pseudo-packets fed to a `FecDecoder` (media or FEC payloads, recovered packets checked
/// for sanity). The pseudo-packets are also turned into consecutive media packets of one
/// SSRC, protected by a `FecEncoder` (for ULPFEC with a level-0 length from the input,
/// and once more with explicit levels), and decoded with every third packet missing: every
/// recovered packet equals the original. Never panics.
pub fn rtp_fec(data: &[u8]) {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    let sch = scheme(sel);
    if let Some(h) = FecHeader::parse(sch, rest) {
        assert!(h.header_len <= rest.len());
        let w = h.write(sch);
        let h2 = FecHeader::parse(sch, &w);
        assert!(h2.is_some(), "rewritten FEC header does not parse");
        if let Some(h2) = h2 {
            assert_eq!(
                (
                    h2.pxcc_recovery,
                    h2.mpt_recovery,
                    h2.length_recovery,
                    h2.ts_recovery
                ),
                (
                    h.pxcc_recovery,
                    h.mpt_recovery,
                    h.length_recovery,
                    h.ts_recovery
                )
            );
            assert_eq!(
                (h2.ssrc, h2.base_seq, &h2.offsets),
                (h.ssrc, h.base_seq, &h.offsets)
            );
        }
        if !h.ulp_levels.is_empty() {
            // Header, level-0 payload, then each level's header and payload: parses to the
            // same levels.
            let mut b = w;
            b.extend_from_slice(&rest[h.header_len..h.header_len + h.protection_len]);
            for (i, l) in h.ulp_levels.iter().enumerate() {
                b.extend(h.write_level(i).unwrap_or_default());
                b.extend_from_slice(&rest[l.payload_offset..l.payload_offset + l.protection_len]);
            }
            let h3 = FecHeader::parse(sch, &b);
            assert!(h3.is_some(), "rewritten ULPFEC levels do not parse");
            if let Some(h3) = h3 {
                let lv = |h: &FecHeader| -> Vec<(Vec<u16>, usize)> {
                    h.ulp_levels
                        .iter()
                        .map(|l| (l.offsets.clone(), l.protection_len))
                        .collect()
                };
                assert_eq!(lv(&h3), lv(&h));
                assert_eq!(h3.offsets, h.offsets);
            }
        }
    }
    if let Some(blocks) = red::parse(rest) {
        let w = red::write(&blocks);
        assert_eq!(red::parse(&w).as_ref(), Some(&blocks));
    }
    if let Some(r) = red::wrap(rest, 100) {
        let back = red::unwrap_primary(&r);
        assert!(back.is_some());
    }
    let _ = red::unwrap_primary(rest);

    let ssrc = 0x0102_0304;
    let mut dec = FecDecoder::new(sch, ssrc);
    let mut media = Vec::new();
    let mut d = rest;
    while let [kind, len, tail @ ..] = d {
        let n = usize::from(*len).min(tail.len());
        let (body, t) = tail.split_at(n);
        d = t;
        let out = if kind & 1 == 0 {
            let mut p = body.to_vec();
            if kind & 2 != 0 && p.len() >= 12 {
                p[0] = 0x80 | (p[0] & 0x3f);
                p[8..12].copy_from_slice(&ssrc.to_be_bytes());
            }
            dec.on_media(&p)
        } else {
            dec.on_fec(body)
        };
        for p in out {
            assert!(p.len() >= 12 && p[0] >> 6 == 2);
            assert_eq!(&p[8..12], &ssrc.to_be_bytes());
        }
        // Media for the encoder: the body after a forced fixed header.
        let mut p = vec![0x80 | (kind & 0x20), kind & 0x80, 0, 0, 0, 0, 0, 0];
        p.extend_from_slice(&ssrc.to_be_bytes());
        p.extend_from_slice(body);
        media.push(p);
    }
    let mut enc = FecEncoder::new(sch, ssrc, sel | 1);
    if sel & 0x10 != 0 {
        enc.set_ulp_level0(Some(usize::from(sel >> 2)));
    }
    let mut dec = FecDecoder::new(sch, ssrc);
    let mut originals = HashMap::new();
    for (i, p) in media.iter_mut().enumerate() {
        let seq = (65_500 + i as u32) as u16;
        p[2..4].copy_from_slice(&seq.to_be_bytes());
        p[4..8].copy_from_slice(&(i as u32 / 4).to_be_bytes());
        originals.insert(seq, p.clone());
        let fec = enc.push(p, i % 5 == 4);
        let mut got = Vec::new();
        if i % 3 != 1 {
            got.extend(dec.on_media(p));
        }
        for f in fec {
            got.extend(dec.on_fec(&f));
        }
        for r in got {
            let seq = u16::from_be_bytes([r[2], r[3]]);
            assert_eq!(Some(&r), originals.get(&seq), "recovered packet differs");
        }
    }
    // Explicit levels over the first (up to) 48 packets: two interleaved level-0 halves of
    // length `l0`, one level 1 over all; decode with packet `lost` missing.
    let group: Vec<&[u8]> = media.iter().take(48).map(Vec::as_slice).collect();
    if group.len() >= 2 && sch == FecScheme::Ulpfec {
        let l0 = usize::from(sel >> 1);
        let k = group.len();
        let half = |r: usize| UlpLevelSpec {
            mask: (r..k).step_by(2).collect(),
            protection_len: l0,
        };
        let all = UlpLevelSpec {
            mask: (0..k).collect(),
            protection_len: usize::from(rest.len() as u8),
        };
        let fec = vec![vec![half(0)], vec![half(1), all]];
        let lost = usize::from(sel) % k;
        if let Some(fec) = enc.encode_ulp(&group, &fec) {
            let mut dec = FecDecoder::new(sch, ssrc);
            let mut got = Vec::new();
            for (i, p) in group.iter().enumerate() {
                if i != lost {
                    got.extend(dec.on_media(p));
                }
            }
            for f in &fec {
                got.extend(dec.on_fec(f));
            }
            for r in &got {
                assert_eq!(r.as_slice(), group[lost], "level recovery differs");
            }
            let body = group[lost].len() - 12;
            if body <= l0 + usize::from(rest.len() as u8) {
                assert_eq!(got.len(), 1, "single loss not recovered");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::rtp_rtcp;

    #[test]
    fn replay_fec_corpus() {
        let n = only_core::fuzzing::replay(env!("CARGO_MANIFEST_DIR"), "rtp_fec", super::rtp_fec);
        assert!(n > 0, "fuzz/corpus/rtp_fec is empty");
        for s in crate::tests_ext::fec_seeds()
            .into_iter()
            .chain(crate::tests_levels::fec_seeds())
        {
            super::rtp_fec(&s);
            for cut in 0..s.len() {
                super::rtp_fec(&s[..cut]);
            }
            for i in 0..s.len() {
                let mut g = s.clone();
                g[i] ^= 0x5a;
                super::rtp_fec(&g);
            }
        }
    }

    #[test]
    fn replay_corpus() {
        let n = only_core::fuzzing::replay(env!("CARGO_MANIFEST_DIR"), "rtp_rtcp", rtp_rtcp);
        assert!(n > 0, "fuzz/corpus/rtp_rtcp is empty");
        for s in crate::tests::seeds()
            .into_iter()
            .chain(crate::tests_levels::seeds())
        {
            rtp_rtcp(&s);
            for cut in 0..s.len() {
                rtp_rtcp(&s[..cut]);
            }
            for i in 0..s.len() {
                let mut g = s.clone();
                g[i] ^= 0x5a;
                rtp_rtcp(&g);
            }
        }
    }

    /// `cargo test -p only-rtp -- --ignored write_corpus`.
    #[test]
    #[ignore = "writes fuzz/corpus"]
    fn write_corpus() {
        only_core::fuzzing::write_target_seeds(
            env!("CARGO_MANIFEST_DIR"),
            "rtp_rtcp",
            &crate::tests::seeds(),
        );
        only_core::fuzzing::write_target_seeds(
            env!("CARGO_MANIFEST_DIR"),
            "rtp_rtcp",
            &crate::tests_levels::seeds(),
        );
        only_core::fuzzing::write_target_seeds(
            env!("CARGO_MANIFEST_DIR"),
            "rtp_fec",
            &crate::tests_levels::fec_seeds(),
        );
        only_core::fuzzing::write_target_seeds(
            env!("CARGO_MANIFEST_DIR"),
            "rtp_fec",
            &crate::tests_ext::fec_seeds(),
        );
    }
}
