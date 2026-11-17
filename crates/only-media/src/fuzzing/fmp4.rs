//! Fragmented MP4 fuzz entry point.

use crate::fmp4::{Demuxer, Event};

/// `fmp4_demux`: the fMP4 demuxer fed the input. `data[0]` bit 0 feeds it in two calls (split
/// at the offset `data[1..3]` names, so an init segment and its fragments can arrive apart),
/// otherwise in one. Checks that packets only come after tracks and index them, and that a
/// sample is never larger than the input.
pub fn fmp4_demux(data: &[u8]) {
    let Some((&cfg, rest)) = data.split_first() else {
        return;
    };
    let mut d = Demuxer::new();
    let mut tracks = 0usize;
    let max = rest.len();
    let mut emit = |e: Event| match e {
        Event::Tracks(t) => tracks = t.len(),
        Event::Packet(p) => {
            assert!(p.track < tracks, "packet before or outside its tracks");
            assert!(p.data.len() <= max, "sample larger than the input");
        }
    };
    if cfg & 1 == 1 && rest.len() >= 2 {
        let at = usize::from(u16::from_be_bytes([rest[0], rest[1]]));
        let rest = &rest[2..];
        let (a, b) = rest.split_at(at.min(rest.len()));
        let _ = d.feed(a, &mut emit);
        let _ = d.feed(b, &mut emit);
    } else {
        let _ = d.feed(rest, &mut emit);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        av::{Packet, Tracks},
        fmp4::{Muxer, write_styp},
    };
    use only_core::fuzzing::{replay, write_target_seeds};

    const DIR: &str = env!("CARGO_MANIFEST_DIR");

    fn flv_sample(data: &[u8]) -> (Tracks, Vec<Packet>) {
        use crate::flv::{Decoder, Demuxer, Event};
        let mut dec = Decoder::new();
        let (mut tracks, mut pkts) = (None, Vec::new());
        for t in Demuxer::new().feed(data).unwrap() {
            for e in dec.write(t.tag_type, t.ts, &t.body) {
                match e {
                    Event::Tracks(t) => tracks = Some(t),
                    Event::Packet(p) => pkts.push(p),
                }
            }
        }
        (tracks.unwrap(), pkts)
    }

    fn ts_sample(data: &[u8]) -> (Tracks, Vec<Packet>) {
        use crate::mpegts::demux::{Demuxer, Event};
        let mut d = Demuxer::new();
        let (mut tracks, mut pkts) = (None, Vec::new());
        let mut emit = |e| match e {
            Event::Tracks(t) => tracks = Some(t),
            Event::Packet(p) => pkts.push(p),
        };
        d.feed(data, &mut emit).unwrap();
        d.flush(&mut emit);
        (tracks.unwrap(), pkts)
    }

    /// Init segments and two small fragments of each sample, whole and split after the init.
    fn seeds() -> Vec<Vec<u8>> {
        let samples = [
            flv_sample(include_bytes!("../../testdata/h264_aac.flv")),
            flv_sample(include_bytes!("../../testdata/h265_aac.flv")),
            ts_sample(include_bytes!("../../testdata/h265_opus.ts")),
        ];
        let mut v = Vec::new();
        for (tracks, pkts) in samples {
            let mut m = Muxer::new(&tracks);
            let init = m.init_segment().to_vec();
            let mut frags = Vec::new();
            for chunk in pkts.chunks(6).take(2) {
                for p in chunk {
                    m.write_packet(p);
                }
                write_styp(&mut frags);
                m.flush(None, &mut frags);
            }
            let mut whole = vec![0];
            whole.extend_from_slice(&init);
            whole.extend_from_slice(&frags);
            v.push(whole);
            let mut split = vec![1];
            split.extend_from_slice(&(init.len() as u16).to_be_bytes());
            split.extend_from_slice(&init);
            split.extend_from_slice(&frags);
            v.push(split);
        }
        v
    }

    #[test]
    fn replay_corpus() {
        assert!(replay(DIR, "fmp4_demux", fmp4_demux) > 0);
    }

    #[test]
    fn seeds_run_clean() {
        for s in seeds() {
            fmp4_demux(&s);
        }
        fmp4_demux(&[]);
        fmp4_demux(&[1, 0]);
        fmp4_demux(&[0, 0, 0, 0, 8, b'm', b'o', b'o', b'v']);
    }

    /// Regenerates the seed files: `cargo test -p only-media --lib write_fmp4_fuzz_seeds -- --ignored`.
    #[test]
    #[ignore]
    fn write_fmp4_fuzz_seeds() {
        write_target_seeds(DIR, "fmp4_demux", &seeds());
    }
}
