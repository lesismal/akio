use crate::av::{Codec, Packet, Time, Track, Tracks, from_ticks};

use super::{
    FLAG_NON_SYNC, Fmp4Error, TFHD_DEFAULT_BASE_IS_MOOF, TRUN_CTS, TRUN_DATA_OFFSET, TRUN_DURATION,
    TRUN_FIRST_SAMPLE_FLAGS, TRUN_FLAGS, TRUN_SIZE,
};

/// Most tracks in a `moov`.
const MAX_TRACKS: usize = 16;
/// Most child boxes looked at in one container (a `moov`, `trak`, `moof`, ...).
const MAX_CHILDREN: usize = 1024;

/// What the demuxer found.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Event {
    /// The tracks of a `moov`: packets after it index these.
    Tracks(Tracks),
    /// One sample.
    Packet(Packet),
}

#[derive(Debug, Clone, Copy, Default)]
struct Defaults {
    duration: u32,
    size: u32,
    flags: u32,
}

#[derive(Debug, Clone)]
struct DTrack {
    id: u32,
    timescale: u32,
    defaults: Defaults,
    /// Decode time (ticks) after the last sample, for a `traf` without `tfdt`.
    next: u64,
}

/// Parses fragmented MP4 back into canonical tracks and packets: an init segment (`moov`)
/// gives the tracks, then each `moof` the packets of the `mdat` after it.
///
/// The input is untrusted: every size is checked against the bytes it claims, the nesting
/// depth is fixed by the box layout it understands (nothing recurses on input), sample counts
/// are bounded by the bytes of their `trun`, and nothing is allocated from a length before it
/// was checked against the input. Errors stop at the box where they are found (packets of the
/// fragments before it were already given).
#[derive(Debug, Default)]
pub struct Demuxer {
    tracks: Vec<DTrack>,
    out: Option<Tracks>,
    /// Sample bytes [`feed`](Self::feed) may still give out (the input's length).
    budget: u64,
}

impl Demuxer {
    /// A demuxer that has not seen an init segment yet.
    pub fn new() -> Demuxer {
        Demuxer::default()
    }

    /// The tracks of the last `moov`, if any.
    pub fn tracks(&self) -> Option<&Tracks> {
        self.out.as_ref()
    }

    /// Parses `data`, a run of whole top-level boxes (an init segment, a media segment, or
    /// both): `moov` emits [`Event::Tracks`], each `moof` the [`Event::Packet`]s whose data
    /// it points at in `data` (offsets are taken relative to `data`). `ftyp`, `styp`, `mdat`
    /// and unknown boxes are skipped.
    pub fn feed(&mut self, data: &[u8], emit: &mut impl FnMut(Event)) -> Result<(), Fmp4Error> {
        self.budget = data.len() as u64;
        for b in Boxes::new(data, usize::MAX) {
            let b = b?;
            match &b.typ {
                b"moov" => {
                    let tracks = self.moov(b.body)?;
                    emit(Event::Tracks(tracks));
                }
                b"moof" => self.moof(data, b.start, b.body, emit)?,
                _ => {}
            }
        }
        Ok(())
    }

    fn moov(&mut self, body: &[u8]) -> Result<Tracks, Fmp4Error> {
        let mut tracks = Vec::new();
        let mut infos = Vec::new();
        let mut trex = Vec::new();
        for b in Boxes::new(body, MAX_CHILDREN) {
            let b = b?;
            match &b.typ {
                b"trak" => {
                    if tracks.len() >= MAX_TRACKS {
                        return Err(Fmp4Error::Limit("tracks"));
                    }
                    let (id, timescale, t) = trak(b.body)?;
                    if infos.iter().any(|d: &DTrack| d.id == id) {
                        return Err(Fmp4Error::Invalid("trak (duplicate track ID)"));
                    }
                    infos.push(DTrack {
                        id,
                        timescale,
                        defaults: Defaults::default(),
                        next: 0,
                    });
                    tracks.push(t);
                }
                b"mvex" => {
                    for e in Boxes::new(b.body, MAX_CHILDREN) {
                        let e = e?;
                        if &e.typ == b"trex" {
                            if trex.len() >= MAX_TRACKS {
                                return Err(Fmp4Error::Limit("tracks"));
                            }
                            let mut r = Reader::new(e.body);
                            r.skip(4)?;
                            let id = r.u32()?;
                            r.skip(4)?; // sample description index
                            let d = Defaults {
                                duration: r.u32()?,
                                size: r.u32()?,
                                flags: r.u32()?,
                            };
                            trex.push((id, d));
                        }
                    }
                }
                _ => {}
            }
        }
        for (id, d) in trex {
            if let Some(t) = infos.iter_mut().find(|t| t.id == id) {
                t.defaults = d;
            }
        }
        let tracks: Tracks = tracks.into();
        self.tracks = infos;
        self.out = Some(tracks.clone());
        Ok(tracks)
    }

    fn moof(
        &mut self,
        data: &[u8],
        moof_start: usize,
        body: &[u8],
        emit: &mut impl FnMut(Event),
    ) -> Result<(), Fmp4Error> {
        if self.out.is_none() {
            return Err(Fmp4Error::Invalid("moof before moov"));
        }
        for b in Boxes::new(body, MAX_CHILDREN) {
            let b = b?;
            if &b.typ == b"traf" {
                self.traf(data, moof_start, b.body, emit)?;
            }
        }
        Ok(())
    }

    fn traf(
        &mut self,
        data: &[u8],
        moof_start: usize,
        body: &[u8],
        emit: &mut impl FnMut(Event),
    ) -> Result<(), Fmp4Error> {
        // tfhd comes first (ISO/IEC 14496-12 8.8.6); tfdt and the truns follow in any order.
        let mut track: Option<usize> = None;
        let mut base = moof_start as u64;
        let mut defaults = Defaults::default();
        let mut time: Option<u64> = None;
        let mut pos: Option<u64> = None;
        for b in Boxes::new(body, MAX_CHILDREN) {
            let b = b?;
            match &b.typ {
                b"tfhd" => {
                    let mut r = Reader::new(b.body);
                    let flags = r.u32()? & 0x00ff_ffff;
                    let id = r.u32()?;
                    let i = self
                        .tracks
                        .iter()
                        .position(|t| t.id == id)
                        .ok_or(Fmp4Error::Invalid("tfhd (unknown track)"))?;
                    defaults = self.tracks[i].defaults;
                    if flags & 0x01 != 0 {
                        base = r.u64()?;
                    } else if flags & TFHD_DEFAULT_BASE_IS_MOOF != 0 {
                        base = moof_start as u64;
                    }
                    if flags & 0x02 != 0 {
                        r.skip(4)?; // sample description index
                    }
                    if flags & 0x08 != 0 {
                        defaults.duration = r.u32()?;
                    }
                    if flags & 0x10 != 0 {
                        defaults.size = r.u32()?;
                    }
                    if flags & 0x20 != 0 {
                        defaults.flags = r.u32()?;
                    }
                    track = Some(i);
                }
                b"tfdt" => {
                    let mut r = Reader::new(b.body);
                    let version = r.u8()?;
                    r.skip(3)?;
                    time = Some(if version == 1 {
                        r.u64()?
                    } else {
                        u64::from(r.u32()?)
                    });
                }
                b"trun" => {
                    let i = track.ok_or(Fmp4Error::Invalid("trun before tfhd"))?;
                    let t = &mut self.tracks[i];
                    let mut now = time.take().unwrap_or(t.next);
                    let mut r = Reader::new(b.body);
                    let version = r.u8()?;
                    let flags = r.u24()?;
                    let count = r.u32()? as usize;
                    let mut at = pos.unwrap_or(base);
                    if flags & TRUN_DATA_OFFSET != 0 {
                        let off = r.u32()? as i32;
                        at = base
                            .checked_add_signed(i64::from(off))
                            .ok_or(Fmp4Error::Invalid("trun data offset"))?;
                    }
                    let first_flags = if flags & TRUN_FIRST_SAMPLE_FLAGS != 0 {
                        Some(r.u32()?)
                    } else {
                        None
                    };
                    let entry = 4
                        * (flags & (TRUN_DURATION | TRUN_SIZE | TRUN_FLAGS | TRUN_CTS)).count_ones()
                            as usize;
                    // The entries must be there before any is read.
                    if count.checked_mul(entry).is_none_or(|n| n > r.remaining()) {
                        return Err(Fmp4Error::Truncated);
                    }
                    for k in 0..count {
                        let dur = if flags & TRUN_DURATION != 0 {
                            r.u32()?
                        } else {
                            defaults.duration
                        };
                        let size = if flags & TRUN_SIZE != 0 {
                            r.u32()?
                        } else {
                            defaults.size
                        };
                        let sflags = if flags & TRUN_FLAGS != 0 {
                            r.u32()?
                        } else if k == 0 {
                            first_flags.unwrap_or(defaults.flags)
                        } else {
                            defaults.flags
                        };
                        let cts = if flags & TRUN_CTS != 0 {
                            let v = r.u32()?;
                            if version == 0 {
                                i64::from(v)
                            } else {
                                i64::from(v as i32)
                            }
                        } else {
                            0
                        };
                        let end = at
                            .checked_add(u64::from(size))
                            .filter(|&e| e <= data.len() as u64)
                            .ok_or(Fmp4Error::Truncated)?;
                        // Samples may point at the same bytes: what is copied out is bounded
                        // by the input (each sample counts at least one byte).
                        self.budget = self
                            .budget
                            .checked_sub(u64::from(size.max(1)))
                            .ok_or(Fmp4Error::Limit("sample bytes"))?;
                        let sample = &data[at as usize..end as usize];
                        at = end;
                        let dts_ticks = i64::try_from(now).unwrap_or(i64::MAX);
                        let dts: Time = from_ticks(dts_ticks, t.timescale);
                        let pts = from_ticks(dts_ticks.saturating_add(cts), t.timescale);
                        emit(Event::Packet(Packet::new(
                            i,
                            dts,
                            pts,
                            sflags & FLAG_NON_SYNC == 0,
                            sample.to_vec(),
                        )));
                        now = now.saturating_add(u64::from(dur));
                    }
                    t.next = now;
                    pos = Some(at);
                }
                _ => {}
            }
        }
        if let (Some(i), Some(t)) = (track, time) {
            // A tfdt without a trun still sets the time.
            self.tracks[i].next = t;
        }
        Ok(())
    }
}

/// Parses a `trak`: (track ID, timescale, track).
fn trak(body: &[u8]) -> Result<(u32, u32, Track), Fmp4Error> {
    let mut id = None;
    let mut timescale = 0;
    let mut track = None;
    for b in Boxes::new(body, MAX_CHILDREN) {
        let b = b?;
        match &b.typ {
            b"tkhd" => {
                let mut r = Reader::new(b.body);
                let version = r.u8()?;
                r.skip(3)?;
                r.skip(if version == 1 { 16 } else { 8 })?;
                id = Some(r.u32()?);
            }
            b"mdia" => {
                for m in Boxes::new(b.body, MAX_CHILDREN) {
                    let m = m?;
                    match &m.typ {
                        b"mdhd" => {
                            let mut r = Reader::new(m.body);
                            let version = r.u8()?;
                            r.skip(3)?;
                            r.skip(if version == 1 { 16 } else { 8 })?;
                            timescale = r.u32()?;
                        }
                        b"minf" => {
                            let stbl = child(m.body, b"stbl")?;
                            if let Some(stsd) = stbl.map(|s| child(s, b"stsd")).transpose()? {
                                track = stsd.map(sample_entry).transpose()?;
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    let id = id.ok_or(Fmp4Error::Invalid("trak (no tkhd)"))?;
    if timescale == 0 {
        return Err(Fmp4Error::Invalid("mdhd (no timescale)"));
    }
    Ok((id, timescale, track.unwrap_or_default()))
}

/// The first child of type `typ`.
fn child<'a>(body: &'a [u8], typ: &[u8; 4]) -> Result<Option<&'a [u8]>, Fmp4Error> {
    for b in Boxes::new(body, MAX_CHILDREN) {
        let b = b?;
        if &b.typ == typ {
            return Ok(Some(b.body));
        }
    }
    Ok(None)
}

/// The track an `stsd` describes (its first entry).
fn sample_entry(stsd: &[u8]) -> Result<Track, Fmp4Error> {
    let mut r = Reader::new(stsd);
    r.skip(4)?;
    if r.u32()? == 0 {
        return Ok(Track::default());
    }
    let Some(e) = Boxes::new(r.rest(), 1).next().transpose()? else {
        return Ok(Track::default());
    };
    let b = e.body;
    match &e.typ {
        b"avc1" | b"avc3" | b"hvc1" | b"hev1" => {
            let h264 = matches!(&e.typ, b"avc1" | b"avc3");
            let (w, h) = (u32::from(be16(b, 24)?), u32::from(be16(b, 26)?));
            let cfg_typ = if h264 { b"avcC" } else { b"hvcC" };
            let cfg = child(b.get(78..).ok_or(Fmp4Error::Truncated)?, cfg_typ)?
                .ok_or(Fmp4Error::Invalid("visual sample entry (no configuration)"))?;
            let codec = if h264 { Codec::H264 } else { Codec::H265 };
            let mut t = Track::video(codec, cfg.to_vec());
            if t.width == 0 && t.height == 0 {
                t.width = w;
                t.height = h;
            }
            Ok(t)
        }
        b"vp08" | b"vp09" | b"av01" => {
            let (w, h) = (u32::from(be16(b, 24)?), u32::from(be16(b, 26)?));
            let kids = b.get(78..).ok_or(Fmp4Error::Truncated)?;
            let (codec, cfg) = if &e.typ == b"av01" {
                let c = child(kids, b"av1C")?.ok_or(Fmp4Error::Invalid("av01 (no av1C)"))?;
                (Codec::Av1, c)
            } else {
                let c = child(kids, b"vpcC")?.ok_or(Fmp4Error::Invalid("vp09 (no vpcC)"))?;
                // A full box: version 1 and flags.
                let c = c.get(4..).ok_or(Fmp4Error::Truncated)?;
                let codec = if &e.typ == b"vp08" {
                    Codec::Vp8
                } else {
                    Codec::Vp9
                };
                (codec, c)
            };
            let mut t = Track::video(codec, cfg.to_vec());
            if t.width == 0 && t.height == 0 {
                t.width = w;
                t.height = h;
            }
            Ok(t)
        }
        b"mp4a" | b"Opus" => {
            let version = be16(b, 8)?;
            let channels = be16(b, 16)?;
            let rate = u32::from(be16(b, 24)?);
            let skip = match version {
                0 => 28,
                1 => 44,
                2 => 64,
                _ => return Err(Fmp4Error::Invalid("audio sample entry version")),
            };
            let kids = b.get(skip..).ok_or(Fmp4Error::Truncated)?;
            if &e.typ == b"mp4a" {
                let esds = child(kids, b"esds")?.ok_or(Fmp4Error::Invalid("mp4a (no esds)"))?;
                let asc = esds_config(esds)?;
                let mut t = Track::aac(asc.to_vec());
                if t.sample_rate == 0 {
                    t.sample_rate = rate;
                }
                if t.channels == 0 {
                    t.channels = channels.min(255) as u8;
                }
                Ok(t)
            } else {
                let d = child(kids, b"dOps")?.ok_or(Fmp4Error::Invalid("Opus (no dOps)"))?;
                let head = dops_to_head(d)?;
                let ch = head[9];
                Ok(Track::audio(Codec::Opus, head, 48_000, ch))
            }
        }
        _ => Ok(Track::default()),
    }
}

/// The `AudioSpecificConfig` in an `esds` (ISO/IEC 14496-1 descriptors).
fn esds_config(esds: &[u8]) -> Result<&[u8], Fmp4Error> {
    let mut r = Reader::new(esds);
    r.skip(4)?;
    let es = expect_desc(&mut r, 0x03)?;
    let mut r = Reader::new(es);
    r.skip(2)?;
    let flags = r.u8()?;
    if flags & 0x80 != 0 {
        r.skip(2)?;
    }
    if flags & 0x40 != 0 {
        let n = r.u8()?;
        r.skip(usize::from(n))?;
    }
    if flags & 0x20 != 0 {
        r.skip(2)?;
    }
    let dcd = expect_desc(&mut r, 0x04)?;
    let mut r = Reader::new(dcd);
    r.skip(13)?;
    expect_desc(&mut r, 0x05)
}

/// Reads descriptors until one with `tag`, returning its payload.
fn expect_desc<'a>(r: &mut Reader<'a>, tag: u8) -> Result<&'a [u8], Fmp4Error> {
    for _ in 0..MAX_CHILDREN {
        let t = r.u8()?;
        let mut n = 0usize;
        for i in 0..4 {
            let b = r.u8()?;
            n = (n << 7) | usize::from(b & 0x7f);
            if b & 0x80 == 0 {
                break;
            }
            if i == 3 {
                return Err(Fmp4Error::Invalid("descriptor length"));
            }
        }
        let body = r.bytes(n)?;
        if t == tag {
            return Ok(body);
        }
    }
    Err(Fmp4Error::Limit("descriptors"))
}

/// An `OpusHead` (little-endian) from a `dOps` (big-endian).
fn dops_to_head(d: &[u8]) -> Result<Vec<u8>, Fmp4Error> {
    let mut r = Reader::new(d);
    if r.u8()? != 0 {
        return Err(Fmp4Error::Invalid("dOps version"));
    }
    let channels = r.u8()?;
    let pre_skip = r.u16()?;
    let rate = r.u32()?;
    let gain = r.u16()?;
    let family = r.u8()?;
    let mut h = Vec::with_capacity(21 + usize::from(channels));
    h.extend_from_slice(b"OpusHead");
    h.push(1);
    h.push(channels);
    h.extend_from_slice(&pre_skip.to_le_bytes());
    h.extend_from_slice(&rate.to_le_bytes());
    h.extend_from_slice(&gain.to_le_bytes());
    h.push(family);
    if family != 0 {
        h.extend_from_slice(r.bytes(2 + usize::from(channels))?);
    }
    Ok(h)
}

fn be16(b: &[u8], at: usize) -> Result<u16, Fmp4Error> {
    b.get(at..at + 2)
        .map(|s| u16::from_be_bytes([s[0], s[1]]))
        .ok_or(Fmp4Error::Truncated)
}

/// One box: where it starts (in the slice iterated), its type and its body.
struct BoxRef<'a> {
    start: usize,
    typ: [u8; 4],
    body: &'a [u8],
}

/// The boxes of a slice, at most `max` of them; an error ends the iteration.
struct Boxes<'a> {
    b: &'a [u8],
    pos: usize,
    left: usize,
}

impl<'a> Boxes<'a> {
    fn new(b: &'a [u8], max: usize) -> Boxes<'a> {
        Boxes {
            b,
            pos: 0,
            left: max,
        }
    }

    fn fail(&mut self, e: Fmp4Error) -> Option<Result<BoxRef<'a>, Fmp4Error>> {
        self.pos = self.b.len();
        Some(Err(e))
    }
}

impl<'a> Iterator for Boxes<'a> {
    type Item = Result<BoxRef<'a>, Fmp4Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let rest = &self.b[self.pos..];
        if rest.is_empty() {
            return None;
        }
        if self.left == 0 {
            return self.fail(Fmp4Error::Limit("boxes"));
        }
        self.left -= 1;
        if rest.len() < 8 {
            return self.fail(Fmp4Error::Truncated);
        }
        let size32 = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]);
        let typ = [rest[4], rest[5], rest[6], rest[7]];
        let (size, hdr) = match size32 {
            0 => (rest.len() as u64, 8),
            1 => {
                let Some(l) = rest.get(8..16) else {
                    return self.fail(Fmp4Error::Truncated);
                };
                let mut a = [0u8; 8];
                a.copy_from_slice(l);
                (u64::from_be_bytes(a), 16)
            }
            n => (u64::from(n), 8),
        };
        if size < hdr as u64 || size > rest.len() as u64 {
            return self.fail(Fmp4Error::Truncated);
        }
        let size = size as usize;
        let start = self.pos;
        self.pos += size;
        Some(Ok(BoxRef {
            start,
            typ,
            body: &rest[hdr..size],
        }))
    }
}

/// A bounds-checked big-endian reader.
struct Reader<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Reader<'a> {
        Reader { b, p: 0 }
    }

    fn remaining(&self) -> usize {
        self.b.len() - self.p
    }

    fn rest(&self) -> &'a [u8] {
        &self.b[self.p..]
    }

    fn bytes(&mut self, n: usize) -> Result<&'a [u8], Fmp4Error> {
        if n > self.remaining() {
            return Err(Fmp4Error::Truncated);
        }
        let s = &self.b[self.p..self.p + n];
        self.p += n;
        Ok(s)
    }

    fn skip(&mut self, n: usize) -> Result<(), Fmp4Error> {
        self.bytes(n).map(|_| ())
    }

    fn u8(&mut self) -> Result<u8, Fmp4Error> {
        Ok(self.bytes(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, Fmp4Error> {
        let b = self.bytes(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u24(&mut self) -> Result<u32, Fmp4Error> {
        let b = self.bytes(3)?;
        Ok(u32::from_be_bytes([0, b[0], b[1], b[2]]))
    }

    fn u32(&mut self) -> Result<u32, Fmp4Error> {
        let b = self.bytes(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&mut self) -> Result<u64, Fmp4Error> {
        let b = self.bytes(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_be_bytes(a))
    }
}

/// Parses one buffer of whole boxes into its tracks and packets (a convenience over
/// [`Demuxer`], for tests).
#[cfg(test)]
pub(crate) fn parse_all(data: &[u8]) -> Result<(Option<Tracks>, Vec<Packet>), Fmp4Error> {
    let mut d = Demuxer::new();
    let mut tracks = None;
    let mut pkts = Vec::new();
    d.feed(data, &mut |e| match e {
        Event::Tracks(t) => tracks = Some(t),
        Event::Packet(p) => pkts.push(p),
    })?;
    Ok((tracks, pkts))
}
