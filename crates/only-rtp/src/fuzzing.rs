//! Fuzz entry points (feature `fuzzing`; not a public API). The `fuzz/` cargo-fuzz project
//! calls them; the unit tests below replay `fuzz/corpus/<target>` on stable.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::fec::{FecDecoder, FecEncoder, FecHeader, FecScheme, red};
use crate::{
    CcfbSender, Extension, ExtensionMap, RecvStream, RrtrResponder, Rtcp, RtpHeader, TmmbrHandler,
    TwccSender, XrBlock, bounded_bitrate, bounding_set, parse_compound, write_compound,
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
/// second write / parse round is stable. What parsed is fed to a `RecvStream`, a
/// `SendStream`, a `TwccSender`, a `CcfbSender`, an `RrtrResponder` and a `TmmbrHandler`
/// (whose bounding set is a subset of the requests). Never panics.
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
                Rtcp::ExtendedReport { ssrc, blocks } => {
                    for b in blocks {
                        match b {
                            XrBlock::ReceiverReferenceTime { ntp } => {
                                rrtr.on_rrtr(now, *ssrc, *ntp);
                            }
                            XrBlock::Dlrr(items) => {
                                for i in items {
                                    let _ = rx.handle_dlrr(0x1234_5678_9abc_def0, i);
                                }
                            }
                            _ => {}
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
/// SSRC, protected by a `FecEncoder`, and decoded with every third packet missing: every
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
}

#[cfg(test)]
mod tests {
    use super::rtp_rtcp;

    #[test]
    fn replay_fec_corpus() {
        let n = only_core::fuzzing::replay(env!("CARGO_MANIFEST_DIR"), "rtp_fec", super::rtp_fec);
        assert!(n > 0, "fuzz/corpus/rtp_fec is empty");
        for s in crate::tests_ext::fec_seeds() {
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
        for s in crate::tests::seeds() {
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
            "rtp_fec",
            &crate::tests_ext::fec_seeds(),
        );
    }
}
