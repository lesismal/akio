//! HLS sample encryption fuzz entry point.

use only_crypto::aes::Aes;

use crate::{
    av::{Codec, MILLISECOND, Packet, Track},
    codec::{h264, h265},
    fmp4,
    mpegts::{
        Muxer,
        sample_aes::{self, SampleKey},
    },
};

/// `h264_sample_encryption`: H.264 parameter sets and slices through the parsers and both
/// sample encryptions. The input is NAL units with 2-byte big-endian lengths (a short last one
/// takes the rest); `data[0]` bit 0 makes the first two the configuration record's SPS and
/// PPS (otherwise they arrive in band). Every NAL unit goes through the SPS / PPS / slice
/// header parsers (a header is never longer than its NAL unit), SAMPLE-AES in MPEG-TS (which
/// must decrypt back to the NAL unit as escaped) and, as access units of up to four NAL
/// units, the `cbcs` fMP4 muxer (fragments flushed now and then).
pub fn h264_sample_encryption(data: &[u8]) {
    let Some((&cfg, mut rest)) = data.split_first() else {
        return;
    };
    let mut nals = Vec::new();
    while rest.len() >= 2 {
        let n = usize::from(u16::from_be_bytes([rest[0], rest[1]])).min(rest.len() - 2);
        if n > 0 {
            nals.push(&rest[2..2 + n]);
        }
        rest = &rest[2 + n..];
    }
    let (sps, pps): (Vec<_>, Vec<_>) = (
        nals.iter().filter_map(|n| h264::sps_info(n)).collect(),
        nals.iter().filter_map(|n| h264::pps_info(n)).collect(),
    );
    let key = SampleKey {
        aes: Aes::new128(&[0x5a; 16]),
        iv: [0xa5; 16],
    };
    for n in &nals {
        if let Some(h) = h264::slice_header_len(n, &sps, &pps) {
            assert!(h <= n.len(), "slice header past its NAL unit");
        }
        let mut enc = Vec::new();
        sample_aes::push_nal(&mut enc, &key, n);
        // An encrypted NAL unit decrypts to itself, emulation prevention made minimal.
        if enc != *n {
            let back = sample_aes::decrypt_nal(&key, &enc);
            assert_eq!(back, sample_aes::escape(&crate::bits::unescape_rbsp(n)));
        }
    }
    let config = if cfg & 1 == 1 && nals.len() >= 2 {
        h264::Config::from_sets(nals[0], nals[1]).encode()
    } else {
        h264::Config::from_sets(&[0x67, 0x42, 0, 0x1e], &[0x68, 0xce]).encode()
    };
    let tracks = [
        Track::video(Codec::H264, config),
        Track::aac(vec![0x12, 0x10]),
    ];
    let mut m = fmp4::Muxer::cbcs(&tracks);
    m.set_sample_key(key.aes.clone());
    let mut ts = Muxer::sample_aes(&tracks);
    ts.set_sample_key(key);
    let mut out = Vec::new();
    for (i, au) in nals.chunks(4).enumerate() {
        let t = i as i64 * 40 * MILLISECOND;
        let p = Packet::new(0, t, t, i % 8 == 0, h264::to_avcc(au.iter().copied()));
        m.write_packet(&p);
        ts.write_packet(&p, &mut out);
        let a = Packet::new(
            1,
            t,
            t,
            true,
            au.first().map_or_else(Vec::new, |n| n.to_vec()),
        );
        m.write_packet(&a);
        ts.write_packet(&a, &mut out);
        if i % 3 == 2 {
            m.flush(Some(t + 40 * MILLISECOND), &mut out);
        }
    }
    m.flush(None, &mut out);
}

/// Splits fuzz input into NAL units with 2-byte big-endian lengths (a short last one takes
/// the rest).
fn nal_units(mut rest: &[u8]) -> Vec<&[u8]> {
    let mut nals = Vec::new();
    while rest.len() >= 2 {
        let n = usize::from(u16::from_be_bytes([rest[0], rest[1]])).min(rest.len() - 2);
        if n > 0 {
            nals.push(&rest[2..2 + n]);
        }
        rest = &rest[2 + n..];
    }
    nals
}

/// `h265_sample_encryption`: H.265 parameter sets and slices through the slice segment header
/// parsers and the `cbcs` fMP4 muxer. The input is NAL units as for
/// [`h264_sample_encryption`]; `data[0]` bit 0 makes the first three the configuration
/// record's VPS, SPS and PPS (otherwise they arrive in band). A header is never longer than
/// its NAL unit, and every access unit (up to four NAL units) the muxer takes decrypts back
/// to itself from its `senc` subsamples.
pub fn h265_sample_encryption(data: &[u8]) {
    let Some((&cfg, rest)) = data.split_first() else {
        return;
    };
    let nals = nal_units(rest);
    let (sps, pps): (Vec<_>, Vec<_>) = (
        nals.iter().filter_map(|n| h265::slice_sps(n)).collect(),
        nals.iter().filter_map(|n| h265::slice_pps(n)).collect(),
    );
    for n in &nals {
        if let Some(h) = h265::slice_header_len(n, &sps, &pps) {
            assert!(h <= n.len(), "slice header past its NAL unit");
        }
    }
    let config = (cfg & 1 == 1 && nals.len() >= 3)
        .then(|| h265::Config::from_sets(nals[0], nals[1], nals[2]))
        .flatten()
        .map_or_else(|| vec![1; 23], |c| c.encode());
    let tracks = [Track::video(Codec::H265, config)];
    let aes = Aes::new128(&[0x5a; 16]);
    let mut m = fmp4::Muxer::cbcs(&tracks);
    m.set_sample_key(aes.clone());
    let mut out = Vec::new();
    let mut want = Vec::new();
    for (i, au) in nals.chunks(4).enumerate() {
        let t = i as i64 * 40 * MILLISECOND;
        let p = Packet::new(0, t, t, i % 8 == 0, h264::to_avcc(au.iter().copied()));
        if m.write_packet(&p) {
            want.push(p.data);
        }
    }
    m.flush(None, &mut out);
    if want.is_empty() {
        return;
    }
    let init = m.init_segment().to_vec();
    let iv = init
        .windows(4)
        .position(|w| w == b"tenc")
        .map(|p| <[u8; 16]>::try_from(&init[p + 29..p + 45]).expect("constant IV"))
        .expect("tenc");
    let (got, subs) = fmp4::cbcs_samples(&out).expect("fragment parses");
    assert_eq!(got.len(), want.len());
    for ((mut d, subs), w) in got.into_iter().zip(subs).zip(&want) {
        let mut at = 0;
        for (clear, prot) in subs {
            at += clear;
            let mut v = iv;
            let mut x = 0;
            while prot - x >= 16 {
                let _ = aes.decrypt_cbc(&mut v, &mut d[at + x..at + x + 16]);
                x += 16;
                x += (prot - x).min(144);
            }
            at += prot;
        }
        assert_eq!(at, d.len());
        assert_eq!(&d, w, "an access unit does not decrypt to itself");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use only_core::fuzzing::{replay, write_target_seeds};

    const DIR: &str = env!("CARGO_MANIFEST_DIR");

    /// The sample's SPS, PPS and first slices, length-prefixed.
    fn seeds() -> Vec<Vec<u8>> {
        use crate::flv::{Decoder, Demuxer, Event};
        let data = std::fs::read(format!("{DIR}/testdata/h264_aac.flv")).unwrap();
        let mut dec = Decoder::new();
        let mut nals: Vec<Vec<u8>> = Vec::new();
        for t in Demuxer::new().feed(&data).unwrap() {
            for e in dec.write(t.tag_type, t.ts, &t.body) {
                match e {
                    Event::Tracks(t) => {
                        let c = h264::Config::parse(&t[0].config).unwrap();
                        nals.push(c.sps[0].clone());
                        nals.push(c.pps[0].clone());
                    }
                    Event::Packet(p) if p.track == 0 => {
                        nals.extend(h264::avcc_nalus(&p.data).into_iter().map(<[u8]>::to_vec));
                    }
                    _ => {}
                }
            }
        }
        let mut v = Vec::new();
        for (cfg, take) in [(1u8, 12usize), (0, 30), (1, 6)] {
            let mut s = vec![cfg];
            for n in nals.iter().take(take) {
                let n = &n[..n.len().min(1200)];
                s.extend_from_slice(&(n.len() as u16).to_be_bytes());
                s.extend_from_slice(n);
            }
            v.push(s);
        }
        v
    }

    #[test]
    fn seeds_run_clean_and_replay() {
        for s in seeds() {
            h264_sample_encryption(&s);
        }
        h264_sample_encryption(&[]);
        h264_sample_encryption(&[1, 0, 1, 0x65]);
        assert!(replay(DIR, "h264_sample_encryption", h264_sample_encryption) > 0);
    }

    /// The H.265 samples' parameter sets and first slices, length-prefixed: the record's
    /// sets with the FLV sample, in band with the multi-slice one.
    fn hevc_seeds() -> Vec<Vec<u8>> {
        use crate::flv::{Decoder, Demuxer, Event};
        let data = std::fs::read(format!("{DIR}/testdata/h265_aac.flv")).unwrap();
        let mut dec = Decoder::new();
        let mut flv: Vec<Vec<u8>> = Vec::new();
        for t in Demuxer::new().feed(&data).unwrap() {
            for e in dec.write(t.tag_type, t.ts, &t.body) {
                match e {
                    Event::Tracks(t) => {
                        let c = h265::Config::parse(&t[0].config).unwrap();
                        flv.extend([c.vps[0].clone(), c.sps[0].clone(), c.pps[0].clone()]);
                    }
                    Event::Packet(p) if p.track == 0 => {
                        flv.extend(h264::avcc_nalus(&p.data).into_iter().map(<[u8]>::to_vec));
                    }
                    _ => {}
                }
            }
        }
        let es = std::fs::read(format!("{DIR}/testdata/h265_slices.hevc")).unwrap();
        let slices: Vec<Vec<u8>> = h264::split_annexb(&es)
            .into_iter()
            .map(<[u8]>::to_vec)
            .collect();
        let mut v = Vec::new();
        for (cfg, nals, take) in [(1u8, &flv, 14usize), (0, &slices, 40), (1, &flv, 5)] {
            let mut s = vec![cfg];
            for n in nals.iter().take(take) {
                let n = &n[..n.len().min(1200)];
                s.extend_from_slice(&(n.len() as u16).to_be_bytes());
                s.extend_from_slice(n);
            }
            v.push(s);
        }
        v
    }

    #[test]
    fn hevc_seeds_run_clean_and_replay() {
        for s in hevc_seeds() {
            h265_sample_encryption(&s);
        }
        h265_sample_encryption(&[]);
        h265_sample_encryption(&[1, 0, 2, 0x26, 0x01]);
        assert!(replay(DIR, "h265_sample_encryption", h265_sample_encryption) > 0);
    }

    /// Regenerates the seed files: `cargo test -p only-media --lib write_hls_fuzz_seeds --
    /// --ignored`.
    #[test]
    #[ignore]
    fn write_hls_fuzz_seeds() {
        write_target_seeds(DIR, "h264_sample_encryption", &seeds());
        write_target_seeds(DIR, "h265_sample_encryption", &hevc_seeds());
    }
}
