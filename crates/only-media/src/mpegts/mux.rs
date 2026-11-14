use crate::{
    av::{Codec, Packet, Track, to_ticks},
    codec::{aac, h264, h265},
};

use super::{
    PACKET_SIZE, PID_FIRST_ES, PID_PAT, PID_PMT, STREAM_AAC, STREAM_H264, STREAM_H265, STREAM_MP3,
    STREAM_PRIVATE, crc32,
};

/// The 33-bit wrap of MPEG timestamps.
const TS_MASK: i64 = (1 << 33) - 1;

#[derive(Debug)]
struct Es {
    pid: u16,
    stream_type: u8,
    stream_id: u8,
    codec: Codec,
    cc: u8,
    /// Parameter sets in Annex B, inserted before keyframes.
    params: Vec<u8>,
    aac: Option<aac::Config>,
    channels: u8,
}

/// Muxes canonical packets into a transport stream: one program, PMT at PID 0x1000, the
/// tracks it can carry from PID 0x100 on in track order, PCR on the first video track (or the
/// first track). Timestamps are the packets' own on the 90 kHz clock, wrapped to 33 bits.
#[derive(Debug)]
pub struct Muxer {
    es: Vec<Option<Es>>,
    pcr_pid: u16,
    pat_cc: u8,
    pmt_cc: u8,
}

impl Muxer {
    /// A muxer for `tracks`; tracks of codecs MPEG-TS cannot carry here are left out.
    pub fn new(tracks: &[Track]) -> Muxer {
        let mut es = Vec::with_capacity(tracks.len());
        let mut pid = PID_FIRST_ES;
        for t in tracks {
            let (stream_type, stream_id) = match t.codec {
                Codec::H264 => (STREAM_H264, 0xe0),
                Codec::H265 => (STREAM_H265, 0xe0),
                Codec::Aac => (STREAM_AAC, 0xc0),
                Codec::Mp3 => (STREAM_MP3, 0xc0),
                Codec::Opus => (STREAM_PRIVATE, 0xbd),
                _ => {
                    es.push(None);
                    continue;
                }
            };
            let params = match t.codec {
                Codec::H264 => h264::Config::parse(&t.config)
                    .map(|c| annexb(c.sps.iter().chain(c.pps.iter())))
                    .unwrap_or_default(),
                Codec::H265 => h265::Config::parse(&t.config)
                    .map(|c| annexb(c.vps.iter().chain(c.sps.iter()).chain(c.pps.iter())))
                    .unwrap_or_default(),
                _ => Vec::new(),
            };
            let aac = (t.codec == Codec::Aac)
                .then(|| aac::Config::parse(&t.config).ok())
                .flatten()
                .or_else(|| {
                    (t.codec == Codec::Aac)
                        .then(|| aac::Config::new(2, t.sample_rate.max(8000), t.channels.max(1)))
                });
            es.push(Some(Es {
                pid,
                stream_type,
                stream_id,
                codec: t.codec,
                cc: 0,
                params,
                aac,
                channels: t.channels.max(1),
            }));
            pid += 1;
        }
        let pcr_pid = es
            .iter()
            .flatten()
            .find(|e| e.codec.is_video())
            .or_else(|| es.iter().flatten().next())
            .map_or(0x1fff, |e| e.pid);
        Muxer {
            es,
            pcr_pid,
            pat_cc: 0,
            pmt_cc: 0,
        }
    }

    /// Whether any track can be muxed.
    pub fn has_tracks(&self) -> bool {
        self.es.iter().any(Option::is_some)
    }

    /// Whether the track at `index` is muxed.
    pub fn carries(&self, index: usize) -> bool {
        self.es.get(index).is_some_and(Option::is_some)
    }

    /// Appends a PAT and a PMT.
    pub fn write_tables(&mut self, out: &mut Vec<u8>) {
        let mut pat = vec![0x00, 0xb0, 0, 0x00, 0x01, 0xc1, 0x00, 0x00];
        pat.extend_from_slice(&[0x00, 0x01, 0xe0 | (PID_PMT >> 8) as u8, PID_PMT as u8]);
        finish_section(&mut pat);
        self.pat_cc = write_section(out, PID_PAT, self.pat_cc, &pat);

        let mut pmt = vec![0x02, 0xb0, 0, 0x00, 0x01, 0xc1, 0x00, 0x00];
        pmt.extend_from_slice(&[
            0xe0 | (self.pcr_pid >> 8) as u8,
            self.pcr_pid as u8,
            0xf0,
            0x00,
        ]);
        for e in self.es.iter().flatten() {
            let mut desc = Vec::new();
            if e.codec == Codec::Opus {
                desc.extend_from_slice(&[0x05, 4, b'O', b'p', b'u', b's']);
                desc.extend_from_slice(&[0x7f, 2, 0x80, e.channels]);
            }
            pmt.push(e.stream_type);
            pmt.extend_from_slice(&[0xe0 | (e.pid >> 8) as u8, e.pid as u8]);
            pmt.extend_from_slice(&[0xf0 | (desc.len() >> 8) as u8, desc.len() as u8]);
            pmt.extend_from_slice(&desc);
        }
        finish_section(&mut pmt);
        self.pmt_cc = write_section(out, PID_PMT, self.pmt_cc, &pmt);
    }

    /// Appends `pkt` as one PES. Returns `false` (and writes nothing) for a track that is not
    /// muxed.
    pub fn write_packet(&mut self, pkt: &Packet, out: &mut Vec<u8>) -> bool {
        let pcr_pid = self.pcr_pid;
        let Some(Some(e)) = self.es.get_mut(pkt.track) else {
            return false;
        };
        let mut payload = Vec::with_capacity(pkt.data.len() + 64);
        match e.codec {
            Codec::H264 | Codec::H265 => {
                let h265 = e.codec == Codec::H265;
                payload.extend_from_slice(if h265 {
                    &[0, 0, 0, 1, 0x46, 0x01, 0x50]
                } else {
                    &[0, 0, 0, 1, 0x09, 0xf0]
                });
                let nalus = h264::avcc_nalus(&pkt.data);
                let has_params = nalus.iter().any(|n| {
                    !n.is_empty()
                        && if h265 {
                            h265::nal_type(n[0]) == h265::NAL_SPS
                        } else {
                            h264::nal_type(n[0]) == h264::NAL_SPS
                        }
                });
                if pkt.keyframe && !has_params {
                    payload.extend_from_slice(&e.params);
                }
                for n in nalus {
                    let aud = if h265 {
                        h265::nal_type(n[0]) == h265::NAL_AUD
                    } else {
                        h264::nal_type(n[0]) == h264::NAL_AUD
                    };
                    if !aud {
                        payload.extend_from_slice(&[0, 0, 0, 1]);
                        payload.extend_from_slice(n);
                    }
                }
            }
            Codec::Aac => {
                if let Some(c) = &e.aac {
                    payload.extend_from_slice(&c.adts_header(pkt.data.len()));
                }
                payload.extend_from_slice(&pkt.data);
            }
            Codec::Opus => {
                payload.extend_from_slice(&[0x7f, 0xe0]);
                let mut n = pkt.data.len();
                while n >= 255 {
                    payload.push(0xff);
                    n -= 255;
                }
                payload.push(n as u8);
                payload.extend_from_slice(&pkt.data);
            }
            _ => payload.extend_from_slice(&pkt.data),
        }
        let dts = to_ticks(pkt.dts, 90_000);
        let pts = to_ticks(pkt.pts, 90_000);
        let video = e.codec.is_video();
        let mut pes = Vec::with_capacity(payload.len() + 19);
        pes.extend_from_slice(&[0, 0, 1, e.stream_id]);
        let with_dts = video && pts != dts;
        let hdr_len: usize = if with_dts { 10 } else { 5 };
        let pes_len = 3 + hdr_len + payload.len();
        let len_field = if video || pes_len > 0xffff {
            0
        } else {
            pes_len as u16
        };
        pes.extend_from_slice(&len_field.to_be_bytes());
        pes.push(0x80);
        pes.push(if with_dts { 0xc0 } else { 0x80 });
        pes.push(hdr_len as u8);
        put_ts(&mut pes, if with_dts { 0x3 } else { 0x2 }, pts);
        if with_dts {
            put_ts(&mut pes, 0x1, dts);
        }
        pes.extend_from_slice(&payload);
        let pcr = (e.pid == pcr_pid).then_some(dts);
        let random_access = pkt.keyframe && (video || pcr.is_some());
        e.cc = write_pes(out, e.pid, e.cc, &pes, pcr, random_access);
        true
    }
}

fn annexb<'a>(sets: impl Iterator<Item = &'a Vec<u8>>) -> Vec<u8> {
    let mut out = Vec::new();
    for s in sets {
        out.extend_from_slice(&[0, 0, 0, 1]);
        out.extend_from_slice(s);
    }
    out
}

fn put_ts(out: &mut Vec<u8>, marker: u8, ts: i64) {
    let t = (ts & TS_MASK) as u64;
    out.push((marker << 4) | (((t >> 30) & 7) as u8) << 1 | 1);
    out.push((t >> 22) as u8);
    out.push((((t >> 15) & 0x7f) as u8) << 1 | 1);
    out.push((t >> 7) as u8);
    out.push(((t & 0x7f) as u8) << 1 | 1);
}

/// Fills in the section length and appends the CRC.
fn finish_section(s: &mut Vec<u8>) {
    let len = s.len() - 3 + 4;
    s[1] = 0xb0 | ((len >> 8) as u8 & 0x0f);
    s[2] = len as u8;
    let crc = crc32(s);
    s.extend_from_slice(&crc.to_be_bytes());
}

fn write_section(out: &mut Vec<u8>, pid: u16, cc: u8, section: &[u8]) -> u8 {
    let start = out.len();
    out.extend_from_slice(&[
        0x47,
        0x40 | (pid >> 8) as u8,
        pid as u8,
        0x10 | (cc & 0xf),
        0x00,
    ]);
    out.extend_from_slice(section);
    out.resize(start + PACKET_SIZE, 0xff);
    (cc + 1) & 0xf
}

/// Splits a PES into TS packets; returns the next continuity counter.
fn write_pes(
    out: &mut Vec<u8>,
    pid: u16,
    mut cc: u8,
    pes: &[u8],
    pcr: Option<i64>,
    random_access: bool,
) -> u8 {
    let mut rest = pes;
    let mut first = true;
    while !rest.is_empty() {
        let start = out.len();
        let pusi = if first { 0x40 } else { 0 };
        out.extend_from_slice(&[0x47, pusi | (pid >> 8) as u8, pid as u8, 0]);
        let mut af: Vec<u8> = Vec::new();
        if first && (pcr.is_some() || random_access) {
            let mut flags = 0u8;
            if random_access {
                flags |= 0x40;
            }
            af.push(0);
            if let Some(p) = pcr {
                flags |= 0x10;
                af.push(flags);
                let base = (p & TS_MASK) as u64;
                af.extend_from_slice(&[
                    (base >> 25) as u8,
                    (base >> 17) as u8,
                    (base >> 9) as u8,
                    (base >> 1) as u8,
                    (((base & 1) as u8) << 7) | 0x7e,
                    0,
                ]);
            } else {
                af.push(flags);
            }
        }
        let room = PACKET_SIZE - 4 - af.len();
        if rest.len() < room {
            // Stuff the adaptation field so the payload ends the packet exactly.
            let need = room - rest.len();
            if af.is_empty() {
                if need == 1 {
                    af.push(0);
                } else {
                    af.push(0);
                    af.push(0);
                    af.resize(need, 0xff);
                }
            } else {
                af.resize(af.len() + need, 0xff);
            }
        }
        if !af.is_empty() {
            af[0] = (af.len() - 1) as u8;
            out[start + 3] = 0x30 | (cc & 0xf);
            out.extend_from_slice(&af);
        } else {
            out[start + 3] = 0x10 | (cc & 0xf);
        }
        let n = (PACKET_SIZE - (out.len() - start)).min(rest.len());
        out.extend_from_slice(&rest[..n]);
        rest = &rest[n..];
        cc = (cc + 1) & 0xf;
        first = false;
    }
    cc
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::av::{MILLISECOND, Track};

    #[test]
    fn packets_are_aligned_and_tables_parse() {
        let tracks = vec![
            Track::video(
                Codec::H264,
                h264::Config::from_sets(&[0x67, 1, 2, 3], &[0x68, 4]).encode(),
            ),
            Track::aac(vec![0x12, 0x10]),
            Track::new(Codec::Unknown, vec![]),
        ];
        let mut m = Muxer::new(&tracks);
        assert!(m.carries(0) && m.carries(1) && !m.carries(2));
        let mut out = Vec::new();
        m.write_tables(&mut out);
        let key = Packet::new(
            0,
            0,
            80 * MILLISECOND,
            true,
            h264::to_avcc([&[0x65u8; 400][..]]),
        );
        assert!(m.write_packet(&key, &mut out));
        for n in [1usize, 170, 182, 183, 184, 185, 1000] {
            let a = Packet::new(1, 0, 0, true, vec![1; n]);
            assert!(m.write_packet(&a, &mut out));
        }
        assert!(!m.write_packet(&Packet::new(2, 0, 0, true, vec![1]), &mut out));
        assert_eq!(out.len() % PACKET_SIZE, 0);
        for p in out.chunks(PACKET_SIZE) {
            assert_eq!(p[0], 0x47);
        }
        // The PAT's CRC covers the section.
        let sec = &out[5..5 + 3 + 13];
        assert_eq!(
            crc32(&sec[..sec.len() - 4]).to_be_bytes(),
            sec[sec.len() - 4..]
        );
        // The keyframe PES carries AUD + SPS + PPS ahead of the slice.
        let s = &out[2 * PACKET_SIZE..3 * PACKET_SIZE];
        let at = s
            .windows(6)
            .position(|w| w == [0, 0, 0, 1, 0x09, 0xf0])
            .unwrap();
        assert_eq!(&s[at + 6..at + 14], &[0, 0, 0, 1, 0x67, 1, 2, 3]);
    }
}
