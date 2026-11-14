//! Fuzz entry point `rtp_codec` (feature `fuzzing`; not a public API). The `fuzz/` cargo-fuzz
//! project calls it; the unit tests below replay `fuzz/corpus/rtp_codec` on stable.

use std::time::{Duration, Instant};

use super::av1::{parse_obus, write_leb128};
use super::h264::{START_CODE, annexb_nals};
use super::{CodecKind, FrameAssembler, MAX_FRAME_SIZE, depacketizer, h264, h265, packetizer};

/// One pseudo-packet of the fuzz input.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PseudoPacket<'a> {
    pub(crate) seq: u64,
    pub(crate) ts: u32,
    pub(crate) marker: bool,
    pub(crate) payload: &'a [u8],
}

/// Splits `data` into pseudo-packets: each is `[flags][len][len bytes]`. Flags: bit 0 marker;
/// bits 1-2 sequence step (+1, +2 = loss, -1 = reorder, +0 = duplicate); bits 3-4 timestamp
/// step (0, +3000, -3000, +2^31). Sequence numbers start at 1000, timestamps just below the
/// 32-bit rollover.
pub(crate) fn split_packets(mut data: &[u8]) -> Vec<PseudoPacket<'_>> {
    let mut out = Vec::new();
    let (mut seq, mut ts) = (1000u64, 0xffff_f000u32);
    while let [flags, len, rest @ ..] = data {
        let n = usize::from(*len).min(rest.len());
        let (payload, tail) = rest.split_at(n);
        data = tail;
        seq = match (flags >> 1) & 3 {
            0 => seq + 1,
            1 => seq + 2,
            2 => seq.saturating_sub(1),
            _ => seq,
        };
        ts = match (flags >> 3) & 3 {
            0 => ts,
            1 => ts.wrapping_add(3000),
            2 => ts.wrapping_sub(3000),
            _ => ts.wrapping_add(1 << 31),
        };
        out.push(PseudoPacket {
            seq,
            ts,
            marker: flags & 1 != 0,
            payload,
        });
    }
    out
}

/// Encodes packets in the [`split_packets`] format (payloads must be at most 255 bytes).
#[cfg(test)]
pub(crate) fn join_packets(pkts: &[(Vec<u8>, bool)], ts_step: bool) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, (p, marker)) in pkts.iter().enumerate() {
        let mut flags = u8::from(*marker);
        if ts_step && i == 0 {
            flags |= 1 << 3;
        }
        out.push(flags);
        out.push(u8::try_from(p.len()).expect("payload fits the seed format"));
        out.extend_from_slice(p);
    }
    out
}

/// What depacketizing the packetized `frame` gives back: the frame itself for formats that
/// carry any bytes, the normalized Annex-B stream (4-byte start codes, dropped units removed)
/// for H.264/H.265, and the normalized OBUs (size fields, temporal delimiters and tile lists
/// removed) for AV1.
pub(crate) fn expected_output(kind: CodecKind, frame: &[u8]) -> Vec<u8> {
    let annexb = |keep: fn(&[u8]) -> bool| {
        let mut out = Vec::new();
        for n in annexb_nals(frame).into_iter().filter(|n| keep(n)) {
            out.extend_from_slice(&START_CODE);
            out.extend_from_slice(n);
        }
        out
    };
    match kind {
        CodecKind::H264 => annexb(h264::sendable),
        CodecKind::H265 => annexb(h265::sendable),
        CodecKind::Av1 => {
            let mut out = Vec::new();
            for o in parse_obus(frame) {
                if matches!(o.obu_type(), 2 | 8) {
                    continue;
                }
                out.push(o.header[0] | 0x02);
                out.extend_from_slice(&o.header[1..]);
                write_leb128(&mut out, o.payload.len());
                out.extend_from_slice(o.payload);
            }
            out
        }
        _ => frame.to_vec(),
    }
}

/// Packetizes `frame` at `mtu`, checks every payload fits, and reassembles it through a
/// [`FrameAssembler`]. Returns the reassembled frame (`None` if there were no payloads).
pub(crate) fn roundtrip(kind: CodecKind, mtu: usize, frame: &[u8]) -> Option<Vec<u8>> {
    let pkts = packetizer(kind).packetize(mtu, frame);
    if pkts.is_empty() {
        return None;
    }
    for (i, (p, marker)) in pkts.iter().enumerate() {
        assert!(
            kind.is_single_packet() || p.len() <= mtu,
            "{kind:?} payload over mtu"
        );
        let last = i + 1 == pkts.len();
        assert_eq!(*marker, last && !kind.is_single_packet(), "{kind:?} marker");
    }
    let mut a = FrameAssembler::new(kind, 30);
    let t = Instant::now();
    for (i, (p, marker)) in pkts.iter().enumerate() {
        a.push(500 + i as u64, 90_000, *marker, p, t);
    }
    let f = a.pop().unwrap_or_else(|| {
        panic!(
            "{kind:?} mtu {mtu}: no complete frame ({} packets)",
            pkts.len()
        )
    });
    assert!(a.pop().is_none());
    assert_eq!(a.buffered(), 0);
    assert!(f.contiguous);
    assert_eq!(
        (f.first_seq, f.last_seq),
        (500, 500 + pkts.len() as u64 - 1)
    );
    Some(f.data)
}

/// `rtp_codec`: the first byte selects the reorder capacity and MTU. The rest is (1) split into
/// pseudo-packets fed to every depacketizer and a [`FrameAssembler`] per codec (never panics;
/// frames come out in sequence order and bounded), and (2) packetized as one frame per codec
/// and reassembled, which must give back the normalized frame (`expected_output`).
pub fn rtp_codec(data: &[u8]) {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    let t0 = Instant::now();
    let pkts = split_packets(rest);
    for kind in CodecKind::ALL {
        let mut d = depacketizer(kind);
        let mut out = Vec::new();
        for p in &pkts {
            let _ = d.is_frame_start(p.payload);
            let _ = d.is_frame_end(p.payload, p.marker);
            let _ = d.is_keyframe(p.payload);
            let _ = d.depacketize(p.payload, &mut out);
        }
        let mut a = FrameAssembler::new(kind, 1 + usize::from(sel % 40));
        let mut last: Option<u64> = None;
        for (i, p) in pkts.iter().enumerate() {
            a.push(
                p.seq,
                p.ts,
                p.marker,
                p.payload,
                t0 + Duration::from_millis(i as u64),
            );
            while let Some(f) = a.pop() {
                assert!(f.first_seq <= f.last_seq);
                assert!(last.is_none_or(|l| f.first_seq > l), "frames out of order");
                assert!(f.data.len() <= MAX_FRAME_SIZE);
                last = Some(f.last_seq);
            }
        }
    }
    let mtu = 1 + usize::from(sel) * 6;
    for kind in CodecKind::ALL {
        let expected = expected_output(kind, rest);
        match roundtrip(kind, mtu, rest) {
            Some(got) => assert!(got == expected, "{kind:?} mtu {mtu}: round trip differs"),
            None => assert!(
                expected.is_empty() || mtu < min_mtu(kind),
                "{kind:?} mtu {mtu}: no payloads for a non-empty frame"
            ),
        }
    }
}

/// Smallest `mtu` each packetizer works with (for frames whose first packet carries no
/// extra headers).
fn min_mtu(kind: CodecKind) -> usize {
    match kind {
        CodecKind::Vp8 => 5,
        CodecKind::Vp9 => 12, // keyframes carry the 8-byte scalability structure
        CodecKind::H264 => 3,
        CodecKind::H265 => 4,
        CodecKind::Av1 => 2,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real packetized frames in the pseudo-packet format, and raw frames.
    fn seeds() -> Vec<Vec<u8>> {
        let mut seeds = Vec::new();
        let frames: Vec<(CodecKind, Vec<u8>)> = vec![
            (CodecKind::Opus, vec![0x78, 1, 2, 3, 4, 5]),
            (CodecKind::Pcmu, vec![0xff; 160]),
            (CodecKind::Vp8, crate::codec::tests::vp8_keyframe(700)),
            (
                CodecKind::Vp9,
                crate::codec::tests::vp9_keyframe(640, 480, 600),
            ),
            (CodecKind::H264, crate::codec::tests::h264_keyframe(500)),
            (CodecKind::H265, crate::codec::tests::h265_keyframe(500)),
            (
                CodecKind::Av1,
                crate::codec::tests::av1_temporal_unit(true, 600),
            ),
        ];
        for (kind, frame) in &frames {
            for mtu in [60usize, 200, 255] {
                let pkts = packetizer(*kind).packetize(mtu, frame);
                let mut s = vec![(mtu / 6) as u8];
                s.extend_from_slice(&join_packets(&pkts, false));
                // A second frame one timestamp step later.
                s.extend_from_slice(&join_packets(&pkts, true));
                seeds.push(s);
            }
            let mut raw = vec![33u8]; // mtu 199
            raw.extend_from_slice(frame);
            seeds.push(raw);
        }
        seeds
    }

    #[test]
    fn seeds_pass() {
        for s in seeds() {
            rtp_codec(&s);
        }
    }

    #[test]
    fn replay_corpus() {
        let n = only_core::fuzzing::replay(env!("CARGO_MANIFEST_DIR"), "rtp_codec", rtp_codec);
        assert!(n > 0, "fuzz/corpus/rtp_codec is empty");
    }

    #[test]
    #[ignore = "writes fuzz/corpus/rtp_codec"]
    fn write_seeds() {
        only_core::fuzzing::write_target_seeds(env!("CARGO_MANIFEST_DIR"), "rtp_codec", &seeds());
    }
}
