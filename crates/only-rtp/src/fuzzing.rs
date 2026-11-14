//! Fuzz entry points (feature `fuzzing`; not a public API). The `fuzz/` cargo-fuzz project
//! calls them; the unit tests below replay `fuzz/corpus/<target>` on stable.

use std::time::{Duration, Instant};

use crate::{
    Extension, ExtensionMap, RecvStream, Rtcp, RtpHeader, TwccSender, parse_compound,
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
/// re-writes to bytes that parse, and a second write / parse round is stable. What parsed
/// is fed to a `RecvStream` and a `TwccSender`. Never panics.
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
        let _ = rx.poll_nack(now + Duration::from_millis(50));
        let _ = rx.report_block(now + Duration::from_millis(60));
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
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::rtp_rtcp;

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
    }
}
