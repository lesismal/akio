//! MP4 file reader fuzz entry point.

use crate::{
    av::SECOND,
    fmp4,
    mp4::{Limits, Locator, Movie, Plan},
    mpegts,
};

/// `mp4_read`: the input is a file. `data[0]` bit 0 has the [`Locator`] fed one header read
/// at a time (as a caller reading through a file does) rather than the whole input; both
/// must find the same `moov`. A movie that parses has every sample walked (each must lie
/// within the input), a segment plan made and its first segments muxed to fMP4 and MPEG-TS.
pub fn mp4_read(data: &[u8]) {
    let Some((&cfg, file)) = data.split_first() else {
        return;
    };
    let limits = Limits {
        max_samples: 1 << 16,
        max_boxes: 1 << 12,
        max_segments: 1 << 12,
        ..Limits::default()
    };
    let whole = Movie::from_bytes(file, &limits);
    if cfg & 1 == 1 {
        let mut loc = Locator::new(file.len() as u64, &limits);
        let found = loop {
            let (off, len) = loc.next_read();
            let s = off as usize;
            match loc.feed(&file[s..s + len]) {
                Ok(Some(at)) => break Some(at),
                Ok(None) => {}
                Err(_) => break None,
            }
        };
        if let Ok(m) = &whole {
            let at = found.expect("the stepwise locator lost the moov");
            assert_eq!((at.offset, at.size), (m.moov_offset, m.moov_size));
        }
    }
    if let Ok(m) = whole {
        exercise(&m, file);
    }
}

/// Walks every sample, plans, and muxes the first segments of a movie read from `file`:
/// nothing may panic, and every sample lies within the file.
pub(crate) fn exercise(m: &Movie, file: &[u8]) {
    for t in &m.tracks {
        for s in t.index.iter(0).take(1 << 16) {
            assert!(s.offset + u64::from(s.size) <= file.len() as u64);
        }
        let _ = t.keyframe_at(SECOND / 2);
    }
    let Ok(plan) = Plan::with_limit(m, SECOND / 2, 1 << 12) else {
        return;
    };
    let _ = plan.vod_playlist(Some("init.mp4"), |i| format!("{i}.m4s"));
    let tracks = m.av_tracks();
    for i in 0..plan.len().min(3) {
        let seg = plan.segment(m, i);
        for r in seg.byte_ranges(m, 64) {
            assert!(r.end <= file.len() as u64);
        }
        let data = [(0u64, file)];
        let mut out = Vec::new();
        let _ = seg.write_fmp4(m, &data, &mut fmp4::Muxer::new(&tracks), &mut out);
        let _ = seg.write_ts(m, &data, &mut mpegts::Muxer::new(&tracks), &mut out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use akio_core::fuzzing::{replay, write_target_seeds};

    const DIR: &str = env!("CARGO_MANIFEST_DIR");

    /// Two of the ffmpeg files (moov at the back, and at the front with Opus), each fed both
    /// ways.
    fn seeds() -> Vec<Vec<u8>> {
        let mut v = Vec::new();
        for f in [
            &include_bytes!("../../testdata/mp4/h264_aac.mp4")[..],
            &include_bytes!("../../testdata/mp4/h265_opus.mp4")[..],
            &include_bytes!("../../testdata/mp4/av1_opus.mp4")[..],
        ] {
            for cfg in [0u8, 1] {
                let mut s = vec![cfg];
                s.extend_from_slice(f);
                v.push(s);
            }
        }
        v
    }

    #[test]
    fn replay_corpus() {
        assert!(replay(DIR, "mp4_read", mp4_read) > 0);
    }

    #[test]
    fn seeds_run_clean() {
        for s in seeds() {
            mp4_read(&s);
        }
        mp4_read(&[]);
        mp4_read(&[1]);
        mp4_read(&[1, 0, 0, 0, 8, b'm', b'o', b'o', b'v']);
        mp4_read(&[1, 0, 0, 0, 0, b'm', b'o', b'o', b'f']);
    }

    /// Regenerates the seed files: `cargo test -p akio-media --lib write_mp4_fuzz_seeds -- --ignored`.
    #[test]
    #[ignore]
    fn write_mp4_fuzz_seeds() {
        write_target_seeds(DIR, "mp4_read", &seeds());
    }
}
