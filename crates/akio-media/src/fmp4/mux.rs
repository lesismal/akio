use akio_crypto::aes::Aes;

use crate::{
    av::{Codec, Packet, Time, Track, to_ticks},
    codec::{aac, av1, h264, h265, opus, vp9},
};

use super::{
    FLAGS_NON_SYNC, FLAGS_SYNC, TFHD_DEFAULT_BASE_IS_MOOF, TRUN_CTS, TRUN_DATA_OFFSET,
    TRUN_DURATION, TRUN_FLAGS, TRUN_SIZE,
};

/// Largest fragment the muxer holds (data offsets in `trun` are 32-bit).
const MAX_FRAGMENT_BYTES: usize = 1 << 30;
/// Most samples of one track in a fragment.
const MAX_FRAGMENT_SAMPLES: usize = 1 << 20;
/// Bytes a sample adds to the `moof` (its `trun` entry), counted in [`Muxer::pending_bytes`].
const SAMPLE_OVERHEAD: usize = 16;
/// The movie timescale (`mvhd`); tracks have their own.
const MOVIE_TIMESCALE: u32 = 1000;
/// The unity matrix of `mvhd` and `tkhd`.
const MATRIX: [u32; 9] = [0x0001_0000, 0, 0, 0, 0x0001_0000, 0, 0, 0, 0x4000_0000];
/// Opus pre-skip when the track has no `OpusHead` (the libopus encoder's look-ahead).
const OPUS_PRE_SKIP: u16 = 312;

#[derive(Debug, Clone, Copy)]
struct Sample {
    /// Decode time in track ticks.
    dts: i64,
    /// Composition offset in track ticks.
    cts: i64,
    size: u32,
    sync: bool,
}

/// One carried track.
#[derive(Debug)]
struct Out {
    id: u32,
    codec: Codec,
    timescale: u32,
    /// Samples of the fragment being built, and their data.
    samples: Vec<Sample>,
    data: Vec<u8>,
    /// Duration of the last sample written out (ticks), 0 before any.
    last_duration: u32,
    /// The codec duration of the newest pending sample (AAC frame, Opus TOC), 0 when unknown.
    natural: u32,
    /// Duration used when nothing else is known.
    fallback: u32,
    /// `cbcs` encryption of the track's samples.
    enc: Option<Box<TrackEnc>>,
}

/// `cbcs` (ISO/IEC 23001-7 10.4) state of an encrypted track.
#[derive(Debug, Default)]
struct TrackEnc {
    /// Video: subsamples (NAL unit and slice headers clear, slice data in a 1:9 pattern);
    /// audio: whole samples, every whole block encrypted.
    video: bool,
    /// H.265 rather than H.264.
    hevc: bool,
    /// The H.264 parameter sets seen (configuration record and in band).
    sps: Vec<h264::SpsInfo>,
    pps: Vec<h264::PpsInfo>,
    /// The H.265 ones.
    hsps: Vec<h265::SliceSps>,
    hpps: Vec<h265::SlicePps>,
    /// `senc` entries of the fragment's samples (video), and their sizes (`saiz`).
    aux: Vec<u8>,
    aux_sizes: Vec<u8>,
}

/// Encrypts a sample just written (`cbcs`), returning the `senc` bytes it added.
#[cold]
#[inline(never)]
fn encrypt_sample(e: &mut TrackEnc, c: &Cbcs, data: &mut [u8]) -> usize {
    let Some(aes) = &c.key else { return 0 };
    let before = e.aux.len();
    if e.video {
        e.video_sample(aes, &c.iv, data);
    } else {
        cbcs_range(aes, &c.iv, data, false);
    }
    e.aux.len() - before + 1
}

/// The pattern of `cbcs` video: one encrypted 16-byte block, nine clear.
const CBCS_CRYPT: u8 = 1;
const CBCS_SKIP: u8 = 9;

/// Encrypts a `cbcs` protected range from the constant IV: video in the 1:9 pattern (every
/// block that is whole), audio every whole block.
fn cbcs_range(aes: &Aes, iv: &[u8; 16], data: &mut [u8], pattern: bool) {
    let mut iv = *iv;
    if !pattern {
        let n = data.len() / 16 * 16;
        let _ = aes.encrypt_cbc(&mut iv, &mut data[..n]);
        return;
    }
    let mut at = 0;
    while data.len() - at >= 16 {
        let _ = aes.encrypt_cbc(&mut iv, &mut data[at..at + 16]);
        at += 16;
        at += (data.len() - at).min(16 * usize::from(CBCS_SKIP));
    }
}

impl TrackEnc {
    /// Keeps the parameter set `nal` (H.264 or H.265) for the slice headers that follow.
    #[inline]
    fn param_set(&mut self, nal: &[u8]) {
        fn keep<T: PartialEq>(v: &mut Vec<T>, x: Option<T>) {
            if let Some(x) = x {
                v.retain(|y| y != &x);
                // Bounded: an id repeats (a new set replaces the old one with that id) and
                // there are at most 32 SPSs and 256 PPSs (64 and 64 in H.265).
                if v.len() >= 256 {
                    v.remove(0);
                }
                v.push(x);
            }
        }
        if self.hevc {
            match h265::nal_type(nal[0]) {
                h265::NAL_SPS => keep(&mut self.hsps, h265::slice_sps(nal)),
                h265::NAL_PPS => keep(&mut self.hpps, h265::slice_pps(nal)),
                _ => {}
            }
        } else {
            match h264::nal_type(nal[0]) {
                h264::NAL_SPS => keep(&mut self.sps, h264::sps_info(nal)),
                h264::NAL_PPS => keep(&mut self.pps, h264::pps_info(nal)),
                _ => {}
            }
        }
    }

    /// The slice header length of `nal` (NAL header included), `None` for NAL units that are
    /// not slices or do not parse.
    #[inline]
    fn header_len(&self, nal: &[u8]) -> Option<usize> {
        if self.hevc {
            h265::slice_header_len(nal, &self.hsps, &self.hpps)
        } else {
            h264::slice_header_len(nal, &self.sps, &self.pps)
        }
    }

    /// Encrypts an H.264 or H.265 sample (AVCC / HVCC, 4-byte lengths) in place and appends
    /// its `senc` entry: every coded slice is a subsample whose clear bytes end with its slice
    /// (segment) header. NAL units of other types (and slices whose header does not parse)
    /// stay clear.
    fn video_sample(&mut self, aes: &Aes, iv: &[u8; 16], data: &mut [u8]) {
        let mut subs: Vec<(usize, usize)> = Vec::new();
        let mut clear = 0usize;
        let mut pos = 0;
        while data.len() - pos >= 4 {
            let n = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]])
                as usize;
            if n == 0 || n > data.len() - pos - 4 {
                break;
            }
            let nal = &data[pos + 4..pos + 4 + n];
            self.param_set(nal);
            let header = self.header_len(nal).filter(|&h| h < n);
            match header {
                Some(h) => {
                    subs.push((clear + 4 + h, n - h));
                    clear = 0;
                    cbcs_range(aes, iv, &mut data[pos + 4 + h..pos + 4 + n], true);
                }
                None => clear += 4 + n,
            }
            pos += 4 + n;
        }
        clear += data.len() - pos;
        if clear > 0 || subs.is_empty() {
            subs.push((clear, 0));
        }
        // BytesOfClearData is 16 bits: a longer clear run is split over subsamples.
        let mut entries: Vec<(u16, u32)> = Vec::with_capacity(subs.len());
        for (mut c, p) in subs {
            while c > 0xffff {
                entries.push((0xffff, 0));
                c -= 0xffff;
            }
            entries.push((c as u16, u32::try_from(p).unwrap_or(u32::MAX)));
        }
        let count = entries.len().min(0xffff);
        self.aux.extend_from_slice(&(count as u16).to_be_bytes());
        for (c, p) in &entries[..count] {
            self.aux.extend_from_slice(&c.to_be_bytes());
            self.aux.extend_from_slice(&p.to_be_bytes());
        }
        self.aux_sizes
            .push(u8::try_from(2 + 6 * count).unwrap_or(0));
    }
}

/// Muxes canonical packets into fragmented MP4: [`init_segment`](Self::init_segment) once per
/// set of tracks, then [`write_packet`](Self::write_packet) for every packet and
/// [`flush`](Self::flush) to cut a `moof` + `mdat` fragment of what was written since the last
/// one.
///
/// Track IDs are 1, 2, ... over the carried tracks in track order. Samples are buffered per
/// track (the buffers are reused from fragment to fragment), so a fragment holds each track's
/// samples in one contiguous run.
#[derive(Debug)]
pub struct Muxer {
    tracks: Vec<Option<Out>>,
    init: Vec<u8>,
    seq: u32,
    pending: usize,
    /// Positions of the `trun` data offsets being patched during a flush (reused).
    offsets: Vec<(usize, usize)>,
    /// `cbcs`: the constant IV and the current key.
    cbcs: Option<Box<Cbcs>>,
}

/// The `cbcs` keying of a muxer.
#[derive(Clone)]
struct Cbcs {
    iv: [u8; 16],
    key: Option<Aes>,
}

impl std::fmt::Debug for Cbcs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cbcs").finish_non_exhaustive()
    }
}

impl Muxer {
    /// A muxer for `tracks`, with its init segment built; tracks of codecs not carried in
    /// fMP4 here (G.711, MP3, unknown, a VP8 / VP9 / AV1 track without a configuration record
    /// that parses) are left out.
    pub fn new(tracks: &[Track]) -> Muxer {
        Muxer::build(tracks, None)
    }

    /// A muxer encrypting with the `cbcs` scheme (ISO/IEC 23001-7) for HLS `SAMPLE-AES`:
    /// H.264, H.265 and AAC tracks only (`encv` / `enca` with a `tenc` holding a random constant
    /// IV); samples are encrypted with the key [`set_sample_key`](Self::set_sample_key) sets
    /// (none are taken before).
    pub(crate) fn cbcs(tracks: &[Track]) -> Muxer {
        let mut iv = [0u8; 16];
        if akio_crypto::rand::fill_random(&mut iv).is_err() {
            // The IV need not be secret nor unpredictable for cbcs; vary it anyway.
            let t = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos());
            iv = t.to_be_bytes();
        }
        Muxer::build(tracks, Some(Box::new(Cbcs { iv, key: None })))
    }

    /// Sets the key samples are encrypted with from now on (a `cbcs` muxer).
    pub(crate) fn set_sample_key(&mut self, key: Aes) {
        if let Some(c) = &mut self.cbcs {
            c.key = Some(key);
        }
    }

    fn build(tracks: &[Track], cbcs: Option<Box<Cbcs>>) -> Muxer {
        let mut outs = Vec::with_capacity(tracks.len());
        let mut id = 0u32;
        for t in tracks {
            let encrypted = matches!(t.codec, Codec::H264 | Codec::H265 | Codec::Aac);
            if !carried(t) || cbcs.is_some() && !encrypted {
                outs.push(None);
                continue;
            }
            let enc = cbcs.as_ref().map(|_| {
                let mut e = TrackEnc {
                    video: t.codec.is_video(),
                    hevc: t.codec == Codec::H265,
                    ..TrackEnc::default()
                };
                let sets: Vec<Vec<u8>> = match t.codec {
                    Codec::H264 => h264::Config::parse(&t.config)
                        .map(|c| c.sps.into_iter().chain(c.pps).collect())
                        .unwrap_or_default(),
                    Codec::H265 => h265::Config::parse(&t.config)
                        .map(|c| c.sps.into_iter().chain(c.pps).collect())
                        .unwrap_or_default(),
                    _ => Vec::new(),
                };
                for s in sets.iter().filter(|s| !s.is_empty()) {
                    e.param_set(s);
                }
                Box::new(e)
            });
            id += 1;
            let timescale = t.clock_rate();
            let fallback = match t.codec {
                Codec::Aac => aac::FRAME_SAMPLES,
                Codec::Opus => 960,
                _ => timescale / 30,
            };
            outs.push(Some(Out {
                id,
                codec: t.codec,
                timescale,
                samples: Vec::new(),
                data: Vec::new(),
                last_duration: 0,
                natural: 0,
                fallback,
                enc,
            }));
        }
        let mut m = Muxer {
            tracks: outs,
            init: Vec::new(),
            seq: 0,
            pending: 0,
            offsets: Vec::new(),
            cbcs,
        };
        m.init = m.build_init(tracks);
        m
    }

    /// Whether any track can be muxed.
    pub fn has_tracks(&self) -> bool {
        self.tracks.iter().any(Option::is_some)
    }

    /// Whether the track at `index` is muxed.
    pub fn carries(&self, index: usize) -> bool {
        self.tracks.get(index).is_some_and(Option::is_some)
    }

    /// The init segment: `ftyp` and `moov`.
    pub fn init_segment(&self) -> &[u8] {
        &self.init
    }

    /// Sets the sequence number (`mfhd`) of the next fragment; later ones follow it. A muxer
    /// starts at 1. For segments made out of order (a VOD file cut on demand), where segment
    /// `i` carries `i + 1`.
    pub fn set_next_sequence(&mut self, seq: u32) {
        self.seq = seq.wrapping_sub(1);
    }

    /// Bytes buffered for the next fragment: sample data plus their `trun` entries.
    pub fn pending_bytes(&self) -> usize {
        self.pending
    }

    /// Whether samples are waiting for [`flush`](Self::flush).
    pub fn has_pending(&self) -> bool {
        self.pending > 0
    }

    /// Buffers `pkt` for the next fragment. Returns `false` (and buffers nothing) for a track
    /// that is not muxed, or when the fragment would pass 1 GiB or 2^20 samples of a track.
    pub fn write_packet(&mut self, pkt: &Packet) -> bool {
        self.write_sample(pkt.track, pkt.dts, pkt.pts, pkt.keyframe, &pkt.data)
    }

    /// [`write_packet`](Self::write_packet) from the packet's parts, without a [`Packet`].
    /// Kept out of line: inlined into the HLS sink's packet path it made that slower.
    #[inline(never)]
    pub(crate) fn write_sample(
        &mut self,
        track: usize,
        dts: Time,
        pts: Time,
        keyframe: bool,
        data: &[u8],
    ) -> bool {
        let Some(Some(t)) = self.tracks.get_mut(track) else {
            return false;
        };
        if t.enc.is_some() && self.cbcs.as_ref().is_none_or(|c| c.key.is_none()) {
            return false; // no key yet
        }
        let add = data.len() + SAMPLE_OVERHEAD;
        if self.pending + add > MAX_FRAGMENT_BYTES || t.samples.len() >= MAX_FRAGMENT_SAMPLES {
            return false;
        }
        let Ok(size) = u32::try_from(data.len()) else {
            return false;
        };
        let d = to_ticks(dts, t.timescale);
        let p = to_ticks(pts, t.timescale);
        t.samples.push(Sample {
            dts: d,
            cts: p - d,
            size,
            sync: keyframe || !t.codec.is_video(),
        });
        let at = t.data.len();
        t.data.extend_from_slice(data);
        if let (Some(e), Some(c)) = (&mut t.enc, &self.cbcs) {
            self.pending += encrypt_sample(e, c, &mut t.data[at..]);
        }
        t.natural = match t.codec {
            Codec::Aac => aac::FRAME_SAMPLES,
            Codec::Opus => opus::packet_samples(data),
            _ => 0,
        };
        self.pending += add;
        true
    }

    /// Appends a fragment (`moof` + `mdat`) of the samples written since the last one, and
    /// returns whether there were any. `end` is the fragment's end time when known (the start
    /// of what follows): the last video sample of each track lasts until then.
    pub fn flush(&mut self, end: Option<Time>, out: &mut Vec<u8>) -> bool {
        if self.pending == 0 {
            return false;
        }
        self.seq = self.seq.wrapping_add(1);
        let moof = open(out, b"moof");
        let mfhd = open_full(out, b"mfhd", 0, 0);
        put32(out, self.seq);
        close(out, mfhd);
        self.offsets.clear();
        for (i, t) in self.tracks.iter_mut().enumerate() {
            let Some(t) = t else { continue };
            if t.samples.is_empty() {
                continue;
            }
            let traf = open(out, b"traf");
            let tfhd = open_full(out, b"tfhd", 0, TFHD_DEFAULT_BASE_IS_MOOF);
            put32(out, t.id);
            close(out, tfhd);
            let tfdt = open_full(out, b"tfdt", 1, 0);
            put64(out, u64::try_from(t.samples[0].dts).unwrap_or(0));
            close(out, tfdt);
            let any_cts = t.samples.iter().any(|s| s.cts != 0);
            let negative = t.samples.iter().any(|s| s.cts < 0);
            let mut flags = TRUN_DATA_OFFSET | TRUN_DURATION | TRUN_SIZE | TRUN_FLAGS;
            if any_cts {
                flags |= TRUN_CTS;
            }
            let trun = open_full(out, b"trun", u8::from(negative), flags);
            put32(out, t.samples.len() as u32);
            self.offsets.push((i, out.len()));
            put32(out, 0);
            let n = t.samples.len();
            for k in 0..n {
                let s = t.samples[k];
                let dur = if k + 1 < n {
                    clamp_u32(t.samples[k + 1].dts - s.dts)
                } else {
                    let to_end = end
                        .filter(|_| t.codec.is_video())
                        .map(|e| to_ticks(e, t.timescale) - s.dts)
                        .filter(|&d| d > 0)
                        .map(clamp_u32);
                    let prev = if n >= 2 {
                        clamp_u32(s.dts - t.samples[n - 2].dts)
                    } else {
                        t.last_duration
                    };
                    to_end
                        .or_else(|| (t.natural > 0).then_some(t.natural))
                        .or_else(|| (prev > 0).then_some(prev))
                        .unwrap_or(t.fallback)
                };
                t.last_duration = dur;
                put32(out, dur);
                put32(out, s.size);
                put32(out, if s.sync { FLAGS_SYNC } else { FLAGS_NON_SYNC });
                if any_cts {
                    let c = s.cts.clamp(i64::from(i32::MIN), i64::from(i32::MAX));
                    if negative {
                        put32(out, c as i32 as u32);
                    } else {
                        put32(out, c as u32);
                    }
                }
            }
            close(out, trun);
            if let Some(e) = t.enc.as_deref_mut().filter(|e| e.video) {
                write_senc(out, moof, e);
            }
            close(out, traf);
        }
        close(out, moof);
        let total: usize = self
            .tracks
            .iter()
            .flatten()
            .map(|t| t.data.len())
            .sum::<usize>();
        if let Ok(size) = u32::try_from(total + 8) {
            put32(out, size);
            out.extend_from_slice(b"mdat");
        } else {
            put32(out, 1);
            out.extend_from_slice(b"mdat");
            put64(out, total as u64 + 16);
        }
        for &(i, at) in &self.offsets {
            let Some(Some(t)) = self.tracks.get_mut(i) else {
                continue;
            };
            let off = u32::try_from(out.len() - moof).unwrap_or(u32::MAX);
            out[at..at + 4].copy_from_slice(&off.to_be_bytes());
            out.extend_from_slice(&t.data);
            t.data.clear();
            t.samples.clear();
        }
        self.pending = 0;
        true
    }

    fn build_init(&self, tracks: &[Track]) -> Vec<u8> {
        let mut out = Vec::with_capacity(1024);
        let ftyp = open(&mut out, b"ftyp");
        out.extend_from_slice(b"iso6");
        put32(&mut out, 0);
        out.extend_from_slice(b"iso6cmfcmp41");
        close(&mut out, ftyp);

        let moov = open(&mut out, b"moov");
        let mvhd = open_full(&mut out, b"mvhd", 0, 0);
        put32(&mut out, 0); // creation time
        put32(&mut out, 0); // modification time
        put32(&mut out, MOVIE_TIMESCALE);
        put32(&mut out, 0); // duration: fragmented
        put32(&mut out, 0x0001_0000); // rate 1.0
        put16(&mut out, 0x0100); // volume 1.0
        out.extend_from_slice(&[0; 10]);
        for m in MATRIX {
            put32(&mut out, m);
        }
        out.extend_from_slice(&[0; 24]);
        let next_id = self.tracks.iter().flatten().count() as u32 + 1;
        put32(&mut out, next_id);
        close(&mut out, mvhd);

        for (t, o) in tracks.iter().zip(&self.tracks) {
            if let Some(o) = o {
                write_trak(&mut out, t, o, self.cbcs.as_ref().map(|c| &c.iv));
            }
        }

        let mvex = open(&mut out, b"mvex");
        for o in self.tracks.iter().flatten() {
            let trex = open_full(&mut out, b"trex", 0, 0);
            put32(&mut out, o.id);
            put32(&mut out, 1); // sample description index
            put32(&mut out, 0); // default duration
            put32(&mut out, 0); // default size
            put32(&mut out, 0); // default flags
            close(&mut out, trex);
        }
        close(&mut out, mvex);
        close(&mut out, moov);
        out
    }
}

/// Whether a track goes into fMP4 (VP8, VP9 and AV1 need their configuration record).
fn carried(t: &Track) -> bool {
    match t.codec {
        Codec::H264 | Codec::H265 | Codec::Aac | Codec::Opus => true,
        Codec::Vp8 | Codec::Vp9 => vp9::Config::parse(&t.config).is_ok(),
        Codec::Av1 => av1::Config::parse(&t.config).is_ok(),
        _ => false,
    }
}

/// The fields of a `VisualSampleEntry` before its child boxes.
fn visual_entry(out: &mut Vec<u8>, t: &Track) {
    out.extend_from_slice(&[0; 6]);
    put16(out, 1); // data reference index
    out.extend_from_slice(&[0; 16]);
    put16(out, t.width.min(0xffff) as u16);
    put16(out, t.height.min(0xffff) as u16);
    put32(out, 0x0048_0000); // 72 dpi
    put32(out, 0x0048_0000);
    put32(out, 0);
    put16(out, 1); // frame count
    out.extend_from_slice(&[0; 32]); // compressor name
    put16(out, 0x0018); // depth
    put16(out, 0xffff);
}

/// Appends a `styp` box (brands `msdh`, `msix`, `cmfs`), which may start a media segment.
pub fn write_styp(out: &mut Vec<u8>) {
    let s = open(out, b"styp");
    out.extend_from_slice(b"msdh");
    put32(out, 0);
    out.extend_from_slice(b"msdhmsixcmfs");
    close(out, s);
}

/// The `saiz`, `saio` and `senc` boxes of an encrypted video track's fragment (`moof` starts
/// at `moof` in `out`); the entries are taken.
fn write_senc(out: &mut Vec<u8>, moof: usize, e: &mut TrackEnc) {
    let n = e.aux_sizes.len() as u32;
    // `saiz` sizes are 8-bit: with a sample of more than 42 subsamples only `senc` is written.
    let sized = e.aux_sizes.iter().all(|&s| s > 0);
    let mut saio_at = None;
    if sized {
        let saiz = open_full(out, b"saiz", 0, 0);
        out.push(0); // default_sample_info_size: per sample
        put32(out, n);
        out.extend_from_slice(&e.aux_sizes);
        close(out, saiz);
        let saio = open_full(out, b"saio", 0, 0);
        put32(out, 1);
        saio_at = Some(out.len());
        put32(out, 0);
        close(out, saio);
    }
    let senc = open_full(out, b"senc", 0, 0x2); // subsample information
    put32(out, n);
    if let Some(at) = saio_at {
        let off = u32::try_from(out.len() - moof).unwrap_or(u32::MAX);
        out[at..at + 4].copy_from_slice(&off.to_be_bytes());
    }
    out.extend_from_slice(&e.aux);
    close(out, senc);
    e.aux.clear();
    e.aux_sizes.clear();
}

/// The `sinf` of an encrypted sample entry: the original format, the `cbcs` scheme and its
/// `tenc` (protected, constant IV `iv`, a zero KID: keys come from the playlist).
fn write_sinf(out: &mut Vec<u8>, original: &[u8; 4], video: bool, iv: &[u8; 16]) {
    let sinf = open(out, b"sinf");
    let frma = open(out, b"frma");
    out.extend_from_slice(original);
    close(out, frma);
    let schm = open_full(out, b"schm", 0, 0);
    out.extend_from_slice(b"cbcs");
    put32(out, 0x0001_0000);
    close(out, schm);
    let schi = open(out, b"schi");
    let tenc = open_full(out, b"tenc", 1, 0);
    out.push(0);
    out.push(if video {
        (CBCS_CRYPT << 4) | CBCS_SKIP
    } else {
        0
    });
    out.push(1); // default_isProtected
    out.push(0); // default_Per_Sample_IV_Size: constant IV
    out.extend_from_slice(&[0; 16]); // default_KID
    out.push(16);
    out.extend_from_slice(iv);
    close(out, tenc);
    close(out, schi);
    close(out, sinf);
}

fn write_trak(out: &mut Vec<u8>, t: &Track, o: &Out, cbcs_iv: Option<&[u8; 16]>) {
    let video = t.codec.is_video();
    let trak = open(out, b"trak");
    let tkhd = open_full(out, b"tkhd", 0, 3); // enabled, in movie
    put32(out, 0);
    put32(out, 0);
    put32(out, o.id);
    put32(out, 0);
    put32(out, 0); // duration
    out.extend_from_slice(&[0; 8]);
    put16(out, 0); // layer
    put16(out, 0); // alternate group
    put16(out, if video { 0 } else { 0x0100 });
    put16(out, 0);
    for m in MATRIX {
        put32(out, m);
    }
    put32(out, if video { t.width.min(0xffff) << 16 } else { 0 });
    put32(out, if video { t.height.min(0xffff) << 16 } else { 0 });
    close(out, tkhd);

    let mdia = open(out, b"mdia");
    let mdhd = open_full(out, b"mdhd", 0, 0);
    put32(out, 0);
    put32(out, 0);
    put32(out, o.timescale);
    put32(out, 0);
    put16(out, 0x55c4); // "und"
    put16(out, 0);
    close(out, mdhd);
    let hdlr = open_full(out, b"hdlr", 0, 0);
    put32(out, 0);
    out.extend_from_slice(if video { b"vide" } else { b"soun" });
    out.extend_from_slice(&[0; 12]);
    out.extend_from_slice(if video {
        b"VideoHandler\0"
    } else {
        b"SoundHandler\0"
    });
    close(out, hdlr);

    let minf = open(out, b"minf");
    if video {
        let vmhd = open_full(out, b"vmhd", 0, 1);
        out.extend_from_slice(&[0; 8]);
        close(out, vmhd);
    } else {
        let smhd = open_full(out, b"smhd", 0, 0);
        put32(out, 0);
        close(out, smhd);
    }
    let dinf = open(out, b"dinf");
    let dref = open_full(out, b"dref", 0, 0);
    put32(out, 1);
    let url = open_full(out, b"url ", 0, 1); // media in the same file
    close(out, url);
    close(out, dref);
    close(out, dinf);

    let stbl = open(out, b"stbl");
    let stsd = open_full(out, b"stsd", 0, 0);
    put32(out, 1);
    match t.codec {
        Codec::Vp8 | Codec::Vp9 => {
            let e = open(
                out,
                if t.codec == Codec::Vp8 {
                    b"vp08"
                } else {
                    b"vp09"
                },
            );
            visual_entry(out, t);
            let c = open_full(out, b"vpcC", 1, 0);
            out.extend_from_slice(&t.config);
            close(out, c);
            close(out, e);
        }
        Codec::Av1 => {
            let e = open(out, b"av01");
            visual_entry(out, t);
            let c = open(out, b"av1C");
            out.extend_from_slice(&t.config);
            close(out, c);
            close(out, e);
        }
        Codec::H264 | Codec::H265 => {
            let h265 = t.codec == Codec::H265;
            let fourcc = if h265 { b"hvc1" } else { b"avc1" };
            let e = open(out, if cbcs_iv.is_some() { b"encv" } else { fourcc });
            visual_entry(out, t);
            let c = open(out, if h265 { b"hvcC" } else { b"avcC" });
            let at = out.len();
            out.extend_from_slice(&t.config);
            // Samples carry 4-byte NAL unit lengths whatever the record said.
            if h265 {
                if let Some(b) = out.get_mut(at + 21) {
                    *b |= 3;
                }
            } else if let Some(b) = out.get_mut(at + 4) {
                *b |= 3;
            }
            close(out, c);
            if let Some(iv) = cbcs_iv {
                write_sinf(out, fourcc, true, iv);
            }
            close(out, e);
        }
        Codec::Aac => {
            let asc = match aac::Config::parse(&t.config) {
                Ok(_) => t.config.clone(),
                Err(_) => aac::Config::new(2, t.sample_rate.max(8000), t.channels.max(1)).encode(),
            };
            let channels = aac::Config::parse(&asc)
                .map_or(0, |c| c.channels)
                .max(t.channels)
                .max(1);
            let e = open(out, if cbcs_iv.is_some() { b"enca" } else { b"mp4a" });
            audio_entry(out, u16::from(channels), o.timescale);
            let esds = open_full(out, b"esds", 0, 0);
            let dsi = desc_size(asc.len());
            let dcd = desc_size(13 + dsi);
            let sl = desc_size(1);
            desc_header(out, 0x03, 3 + dcd + sl);
            put16(out, 0); // ES_ID
            out.push(0); // no dependence, URL or OCR stream
            desc_header(out, 0x04, 13 + dsi);
            out.push(0x40); // MPEG-4 audio
            out.push(0x15); // audio stream
            out.extend_from_slice(&[0; 3]); // buffer size
            put32(out, 0); // max bitrate
            put32(out, 0); // average bitrate
            desc_header(out, 0x05, asc.len());
            out.extend_from_slice(&asc);
            desc_header(out, 0x06, 1);
            out.push(0x02);
            close(out, esds);
            if let Some(iv) = cbcs_iv {
                write_sinf(out, b"mp4a", false, iv);
            }
            close(out, e);
        }
        Codec::Opus => {
            let h = &t.config;
            let head = h.len() >= 19 && h.starts_with(b"OpusHead");
            let channels = if head {
                h[9]
            } else if t.channels > 0 {
                t.channels
            } else {
                2
            };
            let e = open(out, b"Opus");
            audio_entry(out, u16::from(channels.max(1)), 48_000);
            let d = open(out, b"dOps");
            out.push(0); // version
            out.push(channels);
            if head {
                // OpusHead is little-endian, dOps big-endian.
                out.extend_from_slice(&[h[11], h[10]]); // pre-skip
                out.extend_from_slice(&[h[15], h[14], h[13], h[12]]); // input rate
                out.extend_from_slice(&[h[17], h[16]]); // output gain
                let family = h[18];
                let n = usize::from(channels);
                match h.get(19..21 + n) {
                    Some(map) if family != 0 => {
                        out.push(family);
                        out.extend_from_slice(map);
                    }
                    _ => out.push(0),
                }
            } else {
                put16(out, OPUS_PRE_SKIP);
                put32(out, 48_000);
                put16(out, 0);
                out.push(0);
            }
            close(out, d);
            close(out, e);
        }
        _ => {}
    }
    close(out, stsd);
    for (typ, extra) in [(b"stts", 0), (b"stsc", 0), (b"stsz", 1), (b"stco", 0)] {
        let b = open_full(out, typ, 0, 0);
        for _ in 0..extra {
            put32(out, 0); // stsz sample size
        }
        put32(out, 0); // entry / sample count
        close(out, b);
    }
    close(out, stbl);
    close(out, minf);
    close(out, mdia);
    close(out, trak);
}

/// The `AudioSampleEntry` fields (version 0) up to its child boxes.
fn audio_entry(out: &mut Vec<u8>, channels: u16, rate: u32) {
    out.extend_from_slice(&[0; 6]);
    put16(out, 1); // data reference index
    out.extend_from_slice(&[0; 8]);
    put16(out, channels);
    put16(out, 16); // sample size
    put16(out, 0);
    put16(out, 0);
    put32(out, if rate <= 0xffff { rate << 16 } else { 0 });
}

/// Bytes a descriptor of `n` payload bytes takes (tag, length, payload).
fn desc_size(n: usize) -> usize {
    let mut len = 1;
    let mut v = n >> 7;
    while v > 0 {
        len += 1;
        v >>= 7;
    }
    1 + len + n
}

fn desc_header(out: &mut Vec<u8>, tag: u8, n: usize) {
    out.push(tag);
    let mut shift = 0;
    while n >> (shift + 7) > 0 {
        shift += 7;
    }
    while shift > 0 {
        out.push(0x80 | ((n >> shift) & 0x7f) as u8);
        shift -= 7;
    }
    out.push((n & 0x7f) as u8);
}

fn clamp_u32(v: i64) -> u32 {
    v.clamp(0, i64::from(u32::MAX)) as u32
}

fn put16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}

/// Starts a box; [`close`] fills in its size.
fn open(out: &mut Vec<u8>, typ: &[u8; 4]) -> usize {
    let at = out.len();
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(typ);
    at
}

/// Starts a full box (version and flags).
fn open_full(out: &mut Vec<u8>, typ: &[u8; 4], version: u8, flags: u32) -> usize {
    let at = open(out, typ);
    put32(out, (u32::from(version) << 24) | (flags & 0x00ff_ffff));
    at
}

fn close(out: &mut [u8], at: usize) {
    let n = u32::try_from(out.len() - at).unwrap_or(u32::MAX);
    out[at..at + 4].copy_from_slice(&n.to_be_bytes());
}
