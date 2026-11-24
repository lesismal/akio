//! The `moov` parser: a fixed walk of the box layout (never recursive on input) with one box
//! budget for the whole `moov`.

use crate::{
    av::{Codec, Track},
    codec::{h264, h265},
    fmp4::sample_entry,
};

use super::{
    Edit, Limits, MoovLocation, Movie, Mp4Error, Mp4Track,
    index::{SampleIndex, Tables},
};

/// One box of a slice: its type and body.
#[derive(Clone, Copy)]
struct Bx<'a> {
    typ: [u8; 4],
    body: &'a [u8],
}

/// Calls `f` for each box in `b`, counting them against `budget`.
fn children<'a>(
    b: &'a [u8],
    budget: &mut usize,
    mut f: impl FnMut(Bx<'a>, &mut usize) -> Result<(), Mp4Error>,
) -> Result<(), Mp4Error> {
    let mut rest = b;
    while !rest.is_empty() {
        if *budget == 0 {
            return Err(Mp4Error::Limit("boxes"));
        }
        *budget -= 1;
        if rest.len() < 8 {
            return Err(Mp4Error::Truncated);
        }
        let size32 = be32(rest, 0)?;
        let typ = [rest[4], rest[5], rest[6], rest[7]];
        let (size, hdr) = match size32 {
            0 => (rest.len() as u64, 8usize),
            1 => (be64(rest, 8)?, 16),
            n => (u64::from(n), 8),
        };
        if size < hdr as u64 || size > rest.len() as u64 {
            return Err(Mp4Error::Truncated);
        }
        let size = size as usize;
        f(
            Bx {
                typ,
                body: &rest[hdr..size],
            },
            budget,
        )?;
        rest = &rest[size..];
    }
    Ok(())
}

fn be16(b: &[u8], at: usize) -> Result<u16, Mp4Error> {
    b.get(at..at + 2)
        .map(|s| u16::from_be_bytes([s[0], s[1]]))
        .ok_or(Mp4Error::Truncated)
}

pub(super) fn be32(b: &[u8], at: usize) -> Result<u32, Mp4Error> {
    b.get(at..at.wrapping_add(4))
        .map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or(Mp4Error::Truncated)
}

pub(super) fn be64(b: &[u8], at: usize) -> Result<u64, Mp4Error> {
    let s = b.get(at..at.wrapping_add(8)).ok_or(Mp4Error::Truncated)?;
    let mut a = [0u8; 8];
    a.copy_from_slice(s);
    Ok(u64::from_be_bytes(a))
}

/// A full box's version (its flags are not needed here).
fn version(b: &[u8]) -> Result<u8, Mp4Error> {
    b.first().copied().ok_or(Mp4Error::Truncated)
}

pub(super) fn movie(moov: &[u8], at: &MoovLocation, limits: &Limits) -> Result<Movie, Mp4Error> {
    let mut budget = limits.max_boxes;
    // The moov box itself.
    let mut body = None;
    children(moov, &mut budget, |b, _| {
        if body.is_some() || &b.typ != b"moov" {
            return Err(Mp4Error::Invalid("moov"));
        }
        body = Some(b.body);
        Ok(())
    })?;
    let body = body.ok_or(Mp4Error::Invalid("moov"))?;
    let mut m = Movie {
        major_brand: at.major_brand,
        timescale: 0,
        duration: 0,
        file_size: at.file_size,
        moov_offset: at.offset,
        moov_size: moov.len() as u64,
        tracks: Vec::new(),
    };
    let mut traks = Vec::new();
    children(body, &mut budget, |b, _| {
        match &b.typ {
            b"mvhd" => {
                let (ts, dur) = times(b.body)?;
                if ts == 0 {
                    return Err(Mp4Error::Invalid("mvhd (timescale 0)"));
                }
                (m.timescale, m.duration) = (ts, dur);
            }
            b"trak" => {
                if traks.len() >= limits.max_tracks {
                    return Err(Mp4Error::Limit("tracks"));
                }
                traks.push(b.body);
            }
            b"mvex" => return Err(Mp4Error::Fragmented),
            b"cmov" => return Err(Mp4Error::Invalid("moov (compressed)")),
            _ => {}
        }
        Ok(())
    })?;
    if m.timescale == 0 {
        return Err(Mp4Error::Invalid("moov (no mvhd)"));
    }
    for t in traks {
        let mut t = trak(t, &mut budget, at.file_size, limits)?;
        t.shift = shift(&t.edits, m.timescale, t.timescale);
        m.tracks.push(t);
    }
    Ok(m)
}

/// The timescale and duration of an `mvhd` or `mdhd`; an unknown duration (all ones) is 0.
fn times(b: &[u8]) -> Result<(u32, u64), Mp4Error> {
    if version(b)? == 1 {
        let d = be64(b, 24)?;
        Ok((be32(b, 20)?, if d == u64::MAX { 0 } else { d }))
    } else {
        let d = be32(b, 16)?;
        Ok((be32(b, 12)?, if d == u32::MAX { 0 } else { u64::from(d) }))
    }
}

/// The tables of an `stbl`, as slices of the `moov`.
#[derive(Default)]
struct Stbl<'a> {
    stsd: Option<&'a [u8]>,
    t: Tables<'a>,
}

fn set<'a>(slot: &mut Option<&'a [u8]>, b: &'a [u8], what: &'static str) -> Result<(), Mp4Error> {
    if slot.is_some() {
        return Err(Mp4Error::Invalid(what));
    }
    *slot = Some(b);
    Ok(())
}

fn trak(
    body: &[u8],
    budget: &mut usize,
    file_size: u64,
    limits: &Limits,
) -> Result<Mp4Track, Mp4Error> {
    let mut id = None;
    let mut edits = Vec::new();
    let mut udta_name = None;
    let mut mdia = None;
    children(body, budget, |b, budget| {
        match &b.typ {
            b"tkhd" => {
                let at = if version(b.body)? == 1 { 20 } else { 12 };
                id = Some(be32(b.body, at)?);
            }
            b"edts" => children(b.body, budget, |e, _| {
                if &e.typ == b"elst" {
                    edits = elst(e.body, limits)?;
                }
                Ok(())
            })?,
            b"udta" => children(b.body, budget, |u, _| {
                if &u.typ == b"name" {
                    udta_name = Some(text(u.body));
                }
                Ok(())
            })?,
            b"mdia" => set(&mut mdia, b.body, "trak (two mdia)")?,
            _ => {}
        }
        Ok(())
    })?;
    let id = id.ok_or(Mp4Error::Invalid("trak (no tkhd)"))?;
    let mdia = mdia.ok_or(Mp4Error::Invalid("trak (no mdia)"))?;

    let mut mdhd = None;
    let mut handler = [0u8; 4];
    let mut hdlr_name = String::new();
    let mut stbl = Stbl::default();
    let mut have_stbl = false;
    children(mdia, budget, |b, budget| {
        match &b.typ {
            b"mdhd" => {
                let (ts, dur) = times(b.body)?;
                let at = if version(b.body)? == 1 { 32 } else { 20 };
                mdhd = Some((ts, dur, language(be16(b.body, at)?)));
            }
            b"hdlr" => {
                let h = b.body.get(8..12).ok_or(Mp4Error::Truncated)?;
                handler.copy_from_slice(h);
                hdlr_name = b.body.get(24..).map(text).unwrap_or_default();
            }
            b"minf" => children(b.body, budget, |m, budget| {
                if &m.typ == b"stbl" {
                    if have_stbl {
                        return Err(Mp4Error::Invalid("minf (two stbl)"));
                    }
                    have_stbl = true;
                    stbl_boxes(m.body, budget, &mut stbl)?;
                }
                Ok(())
            })?,
            _ => {}
        }
        Ok(())
    })?;
    let (timescale, duration, language) = mdhd.ok_or(Mp4Error::Invalid("mdia (no mdhd)"))?;
    if timescale == 0 {
        return Err(Mp4Error::Invalid("mdhd (timescale 0)"));
    }
    if !have_stbl {
        return Err(Mp4Error::Invalid("minf (no stbl)"));
    }
    let (format, mut track) = match stbl.stsd {
        Some(s) => describe(s)?,
        None => return Err(Mp4Error::Invalid("stbl (no stsd)")),
    };
    if track.codec.is_audio() && track.sample_rate == 0 {
        track.sample_rate = timescale;
    }
    let nal_length = match track.codec {
        Codec::H264 => h264::Config::parse(&track.config).map_or(4, |c| c.length_size),
        Codec::H265 => h265::Config::parse(&track.config).map_or(4, |c| c.length_size),
        _ => 0,
    };
    if nal_length == 3 {
        // A 3-byte length is not allowed by either codec's record.
        return Err(Mp4Error::Invalid("decoder configuration (NAL length size)"));
    }
    let index = SampleIndex::build(&stbl.t, file_size, limits)?;
    Ok(Mp4Track {
        id,
        handler,
        language,
        name: udta_name.unwrap_or(hdlr_name),
        timescale,
        duration,
        format,
        track,
        edits,
        shift: 0,
        index,
        nal_length,
    })
}

fn stbl_boxes<'a>(body: &'a [u8], budget: &mut usize, s: &mut Stbl<'a>) -> Result<(), Mp4Error> {
    children(body, budget, |b, _| {
        let t = &mut s.t;
        match &b.typ {
            b"stsd" => set(&mut s.stsd, b.body, "stbl (two stsd)")?,
            b"stts" => set(&mut t.stts, b.body, "stbl (two stts)")?,
            b"ctts" => set(&mut t.ctts, b.body, "stbl (two ctts)")?,
            b"stss" => set(&mut t.stss, b.body, "stbl (two stss)")?,
            b"stsc" => set(&mut t.stsc, b.body, "stbl (two stsc)")?,
            b"stco" => {
                set(&mut t.chunks, b.body, "stbl (two chunk offset tables)")?;
                t.co64 = false;
            }
            b"co64" => {
                set(&mut t.chunks, b.body, "stbl (two chunk offset tables)")?;
                t.co64 = true;
            }
            b"stsz" => {
                set(&mut t.sizes, b.body, "stbl (two sample size tables)")?;
                t.stz2 = false;
            }
            b"stz2" => {
                set(&mut t.sizes, b.body, "stbl (two sample size tables)")?;
                t.stz2 = true;
            }
            _ => {}
        }
        Ok(())
    })
}

/// The format and codec of an `stsd`'s first entry.
fn describe(stsd: &[u8]) -> Result<([u8; 4], Track), Mp4Error> {
    if be32(stsd, 4)? == 0 {
        return Ok(([0; 4], Track::default()));
    }
    let e = stsd.get(8..16).ok_or(Mp4Error::Truncated)?;
    let format = [e[4], e[5], e[6], e[7]];
    // A sample entry that does not parse leaves the codec unknown: the track's samples are
    // still indexed, and the other tracks still play.
    let track = sample_entry(stsd).unwrap_or_default();
    Ok((format, track))
}

fn elst(b: &[u8], limits: &Limits) -> Result<Vec<Edit>, Mp4Error> {
    let v = version(b)?;
    if v > 1 {
        return Err(Mp4Error::Invalid("elst version"));
    }
    let n = be32(b, 4)? as usize;
    if n > limits.max_edits {
        return Err(Mp4Error::Limit("edits"));
    }
    let entry = if v == 1 { 20 } else { 12 };
    let need = n.checked_mul(entry).and_then(|x| x.checked_add(8));
    if need.is_none_or(|need| need > b.len()) {
        return Err(Mp4Error::Truncated);
    }
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let at = 8 + i * entry;
        let e = if v == 1 {
            Edit {
                duration: be64(b, at)?,
                media_time: be64(b, at + 8)? as i64,
                rate: be32(b, at + 16)? as i32,
            }
        } else {
            Edit {
                duration: u64::from(be32(b, at)?),
                media_time: i64::from(be32(b, at + 4)? as i32),
                rate: be32(b, at + 8)? as i32,
            }
        };
        out.push(e);
    }
    Ok(out)
}

/// The packed ISO 639-2/T code of an `mdhd`; a Macintosh code or anything not three letters
/// is `und`.
fn language(v: u16) -> String {
    if v < 0x400 {
        return "und".to_owned();
    }
    let b = [
        ((v >> 10) & 31) as u8 + 0x60,
        ((v >> 5) & 31) as u8 + 0x60,
        (v & 31) as u8 + 0x60,
    ];
    if b.iter().all(u8::is_ascii_lowercase) {
        String::from_utf8_lossy(&b).into_owned()
    } else {
        "und".to_owned()
    }
}

/// A name string: NUL-terminated UTF-8, or a QuickTime Pascal string (a length byte first);
/// at most 256 bytes are kept.
fn text(b: &[u8]) -> String {
    let mut b = &b[..b.len().min(256)];
    if b.first()
        .is_some_and(|&n| n > 0 && usize::from(n) + 1 == b.len())
    {
        b = &b[1..];
    }
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

/// What the edits add to the media's times, in ticks of the media clock: the empty edits
/// before the first that plays (rescaled from the movie clock), less where that one starts.
/// Both parts are kept within ±`LIMIT` so their difference is in range.
pub(super) fn shift(edits: &[Edit], movie: u32, media: u32) -> i64 {
    const LIMIT: i64 = i64::MAX / 4;
    let (mut delay, mut start) = (0i64, 0i64);
    for e in edits {
        if e.media_time == -1 {
            let d = rescale(e.duration, u64::from(media), u64::from(movie)).min(LIMIT as u64);
            delay = (delay + d as i64).min(LIMIT);
            continue;
        }
        start = e.media_time.clamp(-LIMIT, LIMIT);
        break;
    }
    delay - start
}

/// `a * b / c` rounded to the nearest, saturating.
fn rescale(a: u64, b: u64, c: u64) -> u64 {
    if c == 0 {
        return 0;
    }
    let v = (u128::from(a) * u128::from(b) + u128::from(c / 2)) / u128::from(c);
    u64::try_from(v).unwrap_or(u64::MAX)
}
