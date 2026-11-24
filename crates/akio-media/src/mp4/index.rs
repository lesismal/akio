//! The compact sample index of a track, built from its `stbl` tables.

use std::mem::size_of;

use super::{
    Limits, Mp4Error,
    parse::{be32, be64},
};

/// The raw tables of an `stbl` (box bodies, version and flags included).
#[derive(Default)]
pub(super) struct Tables<'a> {
    pub(super) stts: Option<&'a [u8]>,
    pub(super) ctts: Option<&'a [u8]>,
    pub(super) stss: Option<&'a [u8]>,
    pub(super) stsc: Option<&'a [u8]>,
    pub(super) chunks: Option<&'a [u8]>,
    pub(super) co64: bool,
    pub(super) sizes: Option<&'a [u8]>,
    pub(super) stz2: bool,
}

/// One sample of a track, in ticks of the track's timescale.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct Sample {
    /// Its index in decode order.
    pub index: u32,
    /// Offset of its data in the file.
    pub offset: u64,
    /// Bytes of its data.
    pub size: u32,
    /// Decode time (media clock, before the edit list).
    pub dts: u64,
    /// Composition offset: presentation time minus decode time.
    pub cts: i32,
    /// Duration (`stts`).
    pub duration: u32,
    /// A sync sample (a random access point): listed in `stss`, or every sample without one.
    pub keyframe: bool,
}

/// Sample sizes at the narrowest width that holds them.
#[derive(Debug, Clone)]
enum Sizes {
    Constant(u32),
    U8(Vec<u8>),
    U16(Vec<u16>),
    U32(Vec<u32>),
}

impl Sizes {
    fn get(&self, i: usize) -> u32 {
        match self {
            Sizes::Constant(c) => *c,
            Sizes::U8(v) => u32::from(v[i]),
            Sizes::U16(v) => u32::from(v[i]),
            Sizes::U32(v) => v[i],
        }
    }

    /// Bytes of samples `from..to`.
    fn sum(&self, from: usize, to: usize) -> u64 {
        match self {
            Sizes::Constant(c) => u64::from(*c) * (to - from) as u64,
            Sizes::U8(v) => v[from..to].iter().map(|&x| u64::from(x)).sum(),
            Sizes::U16(v) => v[from..to].iter().map(|&x| u64::from(x)).sum(),
            Sizes::U32(v) => v[from..to].iter().map(|&x| u64::from(x)).sum(),
        }
    }

    fn heap_bytes(&self) -> usize {
        match self {
            Sizes::Constant(_) => 0,
            Sizes::U8(v) => v.capacity(),
            Sizes::U16(v) => v.capacity() * 2,
            Sizes::U32(v) => v.capacity() * 4,
        }
    }
}

/// A run of `stts`: samples from `first` on last `delta` ticks each, the first decoded at
/// `dts`.
#[derive(Debug, Clone, Copy)]
struct TimeRun {
    first: u32,
    delta: u32,
    dts: u64,
}

/// Composition offsets: none, runs (`firsts[k]` starts a run of `offsets[k]`), or one a
/// sample when the runs would take more.
#[derive(Debug, Clone)]
enum Cts {
    None,
    Runs { firsts: Vec<u32>, offsets: Vec<i32> },
    Dense(Vec<i32>),
}

/// A track's sample tables in compact form: sizes at the narrowest width (none when
/// constant), runs of decode deltas and composition offsets, sync samples, and per chunk its
/// file offset and first sample. Lookups are binary searches; [`iter`](Self::iter) walks
/// samples in decode order at constant cost each. Immutable once built, so it can be shared
/// between threads.
#[derive(Debug, Clone)]
pub struct SampleIndex {
    len: u32,
    sizes: Sizes,
    times: Vec<TimeRun>,
    end_dts: u64,
    cts: Cts,
    min_cts: i32,
    /// Sync samples (sorted, 0-based); `None` when every sample is one.
    sync: Option<Vec<u32>>,
    chunk_first: Vec<u32>,
    chunk_offset: Vec<u64>,
    data_bytes: u64,
}

/// The entries of a table: `(count, entries)` after its version, flags and count, checked to
/// be within the box.
fn entries(b: &[u8], skip: usize, entry: usize) -> Result<(usize, &[u8]), Mp4Error> {
    let n = be32(b, skip)? as usize;
    let rest = b.get(skip + 4..).ok_or(Mp4Error::Truncated)?;
    if n.checked_mul(entry).is_none_or(|x| x > rest.len()) {
        return Err(Mp4Error::Truncated);
    }
    Ok((n, rest))
}

impl SampleIndex {
    pub(super) fn build(
        t: &Tables<'_>,
        file_size: u64,
        limits: &Limits,
    ) -> Result<SampleIndex, Mp4Error> {
        let (len, sizes) = match t.sizes {
            None => return Err(Mp4Error::Invalid("stbl (no sample size table)")),
            Some(b) if t.stz2 => stz2(b, limits)?,
            Some(b) => stsz(b, limits)?,
        };
        let (times, end_dts) = stts(t.stts, len)?;
        let (cts, min_cts) = ctts(t.ctts, len)?;
        let sync = t.stss.map(|b| stss(b, len)).transpose()?;
        let (chunk_first, chunk_offset, data_bytes) =
            chunks(t.stsc, t.chunks, t.co64, len, &sizes, file_size)?;
        Ok(SampleIndex {
            len,
            sizes,
            times,
            end_dts,
            cts,
            min_cts,
            sync,
            chunk_first,
            chunk_offset,
            data_bytes,
        })
    }

    /// Number of samples.
    pub fn len(&self) -> u32 {
        self.len
    }

    /// Whether the track has no samples.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Sample `i`, `None` past the end. O(log n).
    pub fn sample(&self, i: u32) -> Option<Sample> {
        if i >= self.len {
            return None;
        }
        let r = self.times[self.time_run(i)];
        let c = self.chunk_of(i);
        let first = self.chunk_first[c] as usize;
        let offset = self.chunk_offset[c] + self.sizes.sum(first, i as usize);
        Some(Sample {
            index: i,
            offset,
            size: self.sizes.get(i as usize),
            dts: r.dts + u64::from(i - r.first) * u64::from(r.delta),
            cts: self.cts_of(i),
            duration: r.delta,
            keyframe: self.is_keyframe(i),
        })
    }

    /// The samples from `from` on, in decode order.
    pub fn iter(&self, from: u32) -> Samples<'_> {
        let from = from.min(self.len);
        let mut s = Samples {
            ix: self,
            i: from,
            end: self.len,
            run: 0,
            cts_run: 0,
            sync: 0,
            chunk: 0,
            offset: 0,
        };
        if from < self.len {
            s.run = self.time_run(from);
            if let Cts::Runs { firsts, .. } = &self.cts {
                s.cts_run = firsts.partition_point(|&f| f <= from).saturating_sub(1);
            }
            if let Some(v) = &self.sync {
                s.sync = v.partition_point(|&k| k < from);
            }
            s.chunk = self.chunk_of(from);
            let first = self.chunk_first[s.chunk] as usize;
            s.offset = self.chunk_offset[s.chunk] + self.sizes.sum(first, from as usize);
        }
        s
    }

    /// Samples `from..to` in decode order.
    pub fn range(&self, from: u32, to: u32) -> Samples<'_> {
        let mut s = self.iter(from);
        s.end = to.min(self.len).max(s.i);
        s
    }

    /// Whether sample `i` is a sync sample.
    pub fn is_keyframe(&self, i: u32) -> bool {
        match &self.sync {
            None => i < self.len,
            Some(v) => v.binary_search(&i).is_ok(),
        }
    }

    /// The sync samples (sorted), or `None` when every sample is one (no `stss`).
    pub fn sync_samples(&self) -> Option<&[u32]> {
        self.sync.as_deref()
    }

    /// The last sync sample at or before `i`.
    pub fn keyframe_at_or_before(&self, i: u32) -> Option<u32> {
        if self.len == 0 {
            return None;
        }
        let i = i.min(self.len - 1);
        match &self.sync {
            None => Some(i),
            Some(v) => v.partition_point(|&k| k <= i).checked_sub(1).map(|p| v[p]),
        }
    }

    /// The first sync sample at or after `i`.
    pub fn keyframe_at_or_after(&self, i: u32) -> Option<u32> {
        match &self.sync {
            None => (i < self.len).then_some(i),
            Some(v) => v.get(v.partition_point(|&k| k < i)).copied(),
        }
    }

    /// The first sample decoded at or after `dts` (ticks of the media clock); `len()` when
    /// none is.
    pub fn first_at_or_after_dts(&self, dts: u64) -> u32 {
        // The run whose start is the last at or before `dts`.
        let p = self.times.partition_point(|r| r.dts <= dts);
        if p == 0 {
            return 0;
        }
        let r = self.times[p - 1];
        let count = self.run_end(p - 1) - r.first;
        let into = dts - r.dts;
        let k = if r.delta == 0 {
            u64::from(into > 0) * u64::from(count)
        } else {
            into.div_ceil(u64::from(r.delta))
        };
        if k >= u64::from(count) {
            self.run_end(p - 1)
        } else {
            r.first + k as u32
        }
    }

    /// Decode time of the first sample (0 without samples).
    pub fn first_dts(&self) -> u64 {
        self.times.first().map_or(0, |r| r.dts)
    }

    /// Decode time at the end of the last sample.
    pub fn end_dts(&self) -> u64 {
        self.end_dts
    }

    /// The smallest composition offset (negative with `ctts` version 1): the decode delay a
    /// player needs so that no presentation time is before its decode time.
    pub fn min_cts(&self) -> i32 {
        self.min_cts
    }

    /// Bytes of all samples' data.
    pub fn data_bytes(&self) -> u64 {
        self.data_bytes
    }

    /// Heap bytes this index takes.
    pub fn heap_bytes(&self) -> usize {
        let cts = match &self.cts {
            Cts::None => 0,
            Cts::Runs { firsts, offsets } => firsts.capacity() * 4 + offsets.capacity() * 4,
            Cts::Dense(v) => v.capacity() * 4,
        };
        self.sizes.heap_bytes()
            + self.times.capacity() * size_of::<TimeRun>()
            + cts
            + self.sync.as_ref().map_or(0, |v| v.capacity() * 4)
            + self.chunk_first.capacity() * 4
            + self.chunk_offset.capacity() * 8
    }

    fn time_run(&self, i: u32) -> usize {
        self.times.partition_point(|r| r.first <= i) - 1
    }

    fn run_end(&self, run: usize) -> u32 {
        self.times.get(run + 1).map_or(self.len, |r| r.first)
    }

    fn chunk_of(&self, i: u32) -> usize {
        self.chunk_first.partition_point(|&f| f <= i) - 1
    }

    fn cts_of(&self, i: u32) -> i32 {
        match &self.cts {
            Cts::None => 0,
            Cts::Runs { firsts, offsets } => {
                // Past the last run (a short ctts): 0.
                let p = firsts.partition_point(|&f| f <= i);
                if p == 0 { 0 } else { offsets[p - 1] }
            }
            Cts::Dense(v) => v.get(i as usize).copied().unwrap_or(0),
        }
    }
}

/// Samples of a [`SampleIndex`] in decode order, at constant cost each.
#[derive(Debug, Clone)]
pub struct Samples<'a> {
    ix: &'a SampleIndex,
    i: u32,
    end: u32,
    run: usize,
    cts_run: usize,
    sync: usize,
    chunk: usize,
    offset: u64,
}

impl Iterator for Samples<'_> {
    type Item = Sample;

    fn next(&mut self) -> Option<Sample> {
        let ix = self.ix;
        let i = self.i;
        if i >= self.end {
            return None;
        }
        while self.run + 1 < ix.times.len() && ix.times[self.run + 1].first <= i {
            self.run += 1;
        }
        // Skip empty chunks and move to the one holding `i`.
        if self.chunk + 1 < ix.chunk_first.len() && ix.chunk_first[self.chunk + 1] <= i {
            while self.chunk + 1 < ix.chunk_first.len() && ix.chunk_first[self.chunk + 1] <= i {
                self.chunk += 1;
            }
            self.offset = ix.chunk_offset[self.chunk];
        }
        let r = ix.times[self.run];
        let cts = match &ix.cts {
            Cts::None => 0,
            Cts::Runs { firsts, offsets } => {
                while self.cts_run + 1 < firsts.len() && firsts[self.cts_run + 1] <= i {
                    self.cts_run += 1;
                }
                if firsts.first().is_some_and(|&f| f <= i) {
                    offsets[self.cts_run]
                } else {
                    0
                }
            }
            Cts::Dense(v) => v.get(i as usize).copied().unwrap_or(0),
        };
        let keyframe = match &ix.sync {
            None => true,
            Some(v) => {
                while self.sync < v.len() && v[self.sync] < i {
                    self.sync += 1;
                }
                v.get(self.sync) == Some(&i)
            }
        };
        let size = ix.sizes.get(i as usize);
        let s = Sample {
            index: i,
            offset: self.offset,
            size,
            dts: r.dts + u64::from(i - r.first) * u64::from(r.delta),
            cts,
            duration: r.delta,
            keyframe,
        };
        self.offset += u64::from(size);
        self.i += 1;
        Some(s)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let n = (self.end - self.i) as usize;
        (n, Some(n))
    }
}

impl ExactSizeIterator for Samples<'_> {}

fn stsz(b: &[u8], limits: &Limits) -> Result<(u32, Sizes), Mp4Error> {
    let constant = be32(b, 4)?;
    let n = be32(b, 8)?;
    if n > limits.max_samples {
        return Err(Mp4Error::Limit("samples"));
    }
    if constant != 0 {
        return Ok((n, Sizes::Constant(constant)));
    }
    let (n, e) = entries(b, 8, 4)?;
    let max = (0..n)
        .map(|i| be32(e, i * 4).unwrap_or(0))
        .max()
        .unwrap_or(0);
    let sizes = if u8::try_from(max).is_ok() {
        Sizes::U8((0..n).map(|i| e[i * 4 + 3]).collect())
    } else if u16::try_from(max).is_ok() {
        Sizes::U16(
            (0..n)
                .map(|i| u16::from_be_bytes([e[i * 4 + 2], e[i * 4 + 3]]))
                .collect(),
        )
    } else {
        Sizes::U32((0..n).map(|i| be32(e, i * 4).unwrap_or(0)).collect())
    };
    Ok((n as u32, sizes))
}

fn stz2(b: &[u8], limits: &Limits) -> Result<(u32, Sizes), Mp4Error> {
    let field = *b.get(7).ok_or(Mp4Error::Truncated)?;
    let n = be32(b, 8)?;
    if n > limits.max_samples {
        return Err(Mp4Error::Limit("samples"));
    }
    let n = n as usize;
    let e = b.get(12..).ok_or(Mp4Error::Truncated)?;
    let bytes = match field {
        4 => n.div_ceil(2),
        8 => n,
        16 => n * 2,
        _ => return Err(Mp4Error::Invalid("stz2 field size")),
    };
    if bytes > e.len() {
        return Err(Mp4Error::Truncated);
    }
    let sizes = match field {
        4 => Sizes::U8(
            (0..n)
                .map(|i| {
                    let x = e[i / 2];
                    if i % 2 == 0 { x >> 4 } else { x & 15 }
                })
                .collect(),
        ),
        8 => Sizes::U8(e[..n].to_vec()),
        _ => Sizes::U16(
            (0..n)
                .map(|i| u16::from_be_bytes([e[2 * i], e[2 * i + 1]]))
                .collect(),
        ),
    };
    Ok((n as u32, sizes))
}

/// The `stts` runs covering `len` samples, and the decode time after the last.
fn stts(b: Option<&[u8]>, len: u32) -> Result<(Vec<TimeRun>, u64), Mp4Error> {
    let Some(b) = b else {
        return if len == 0 {
            Ok((Vec::new(), 0))
        } else {
            Err(Mp4Error::Invalid("stbl (no stts)"))
        };
    };
    let (n, e) = entries(b, 4, 8)?;
    let mut runs = Vec::new();
    let (mut first, mut dts) = (0u32, 0u64);
    for k in 0..n {
        if first >= len {
            break;
        }
        let count = be32(e, k * 8)?.min(len - first);
        let delta = be32(e, k * 8 + 4)?;
        if count == 0 {
            continue;
        }
        runs.push(TimeRun { first, delta, dts });
        dts = u64::from(count)
            .checked_mul(u64::from(delta))
            .and_then(|d| d.checked_add(dts))
            .filter(|&d| d <= i64::MAX as u64 / 4)
            .ok_or(Mp4Error::Invalid("stts (decode time overflow)"))?;
        first += count;
    }
    if first < len {
        return Err(Mp4Error::Invalid("stts (fewer samples than stsz)"));
    }
    runs.shrink_to_fit();
    Ok((runs, dts))
}

fn ctts(b: Option<&[u8]>, len: u32) -> Result<(Cts, i32), Mp4Error> {
    let Some(b) = b else {
        return Ok((Cts::None, 0));
    };
    if b.first().copied().unwrap_or(0) > 1 {
        return Err(Mp4Error::Invalid("ctts version"));
    }
    let (n, e) = entries(b, 4, 8)?;
    // Version 0 offsets are unsigned in the standard; read signed as ffmpeg does, since
    // writers put negative offsets in version 0 too.
    let mut runs: Vec<(u32, u32, i32)> = Vec::with_capacity(n.min(len as usize));
    let mut first = 0u32;
    let mut min = i32::MAX;
    for k in 0..n {
        if first >= len {
            break;
        }
        let count = be32(e, k * 8)?.min(len - first);
        let off = be32(e, k * 8 + 4)? as i32;
        if count == 0 {
            continue;
        }
        min = min.min(off);
        runs.push((first, count, off));
        first += count;
    }
    if first < len && len > 0 {
        min = min.min(0); // samples past the table have offset 0
    }
    if runs.is_empty() {
        return Ok((Cts::None, 0));
    }
    // Dense when one offset a sample takes no more than two words a run.
    let cts = if (len as usize) <= runs.len() * 2 {
        let mut v = vec![0i32; len as usize];
        for &(f, c, o) in &runs {
            v[f as usize..(f + c) as usize].fill(o);
        }
        Cts::Dense(v)
    } else {
        let mut firsts = Vec::with_capacity(runs.len() + 1);
        let mut offsets = Vec::with_capacity(runs.len() + 1);
        for &(f, _, o) in &runs {
            firsts.push(f);
            offsets.push(o);
        }
        if first < len {
            firsts.push(first);
            offsets.push(0);
        }
        Cts::Runs { firsts, offsets }
    };
    Ok((cts, min))
}

fn stss(b: &[u8], len: u32) -> Result<Vec<u32>, Mp4Error> {
    let (n, e) = entries(b, 4, 4)?;
    let mut v = Vec::with_capacity(n);
    let mut sorted = true;
    for k in 0..n {
        let s = be32(e, k * 4)?;
        if s == 0 || s > len {
            continue; // 1-based; out of range entries are ignored
        }
        if v.last().is_some_and(|&l| l >= s - 1) {
            sorted = false;
        }
        v.push(s - 1);
    }
    if !sorted {
        v.sort_unstable();
        v.dedup();
    }
    v.shrink_to_fit();
    Ok(v)
}

/// Per chunk its first sample and offset, and the bytes of all samples: every sample must be
/// in a chunk and every chunk's samples within the file.
fn chunks(
    stsc: Option<&[u8]>,
    offsets: Option<&[u8]>,
    co64: bool,
    len: u32,
    sizes: &Sizes,
    file_size: u64,
) -> Result<(Vec<u32>, Vec<u64>, u64), Mp4Error> {
    let (Some(stsc), Some(offsets)) = (stsc, offsets) else {
        return if len == 0 {
            Ok((vec![0], vec![0], 0))
        } else {
            Err(Mp4Error::Invalid("stbl (no stsc or chunk offsets)"))
        };
    };
    let entry = if co64 { 8 } else { 4 };
    let (nchunks, co) = entries(offsets, 4, entry)?;
    let (nstsc, sc) = entries(stsc, 4, 12)?;
    let mut first = Vec::with_capacity(nchunks.max(1));
    let mut offs = Vec::with_capacity(nchunks.max(1));
    let (mut sample, mut total) = (0u32, 0u64);
    let mut prev = 0u32;
    for k in 0..nstsc {
        let fc = be32(sc, k * 12)?;
        if fc <= prev {
            return Err(Mp4Error::Invalid("stsc (first chunks not increasing)"));
        }
        prev = fc;
    }
    let mut e = 0usize; // stsc entries in force: those before `e`
    for c in 0..nchunks {
        // Advance past every entry whose first chunk (1-based) is at or before c + 1.
        while e < nstsc && be32(sc, e * 12)? as usize <= c + 1 {
            e += 1;
        }
        let per = if e == 0 {
            0 // chunks before the first entry hold no samples
        } else {
            be32(sc, (e - 1) * 12 + 4)?
        };
        let off = if co64 {
            be64(co, c * 8)?
        } else {
            u64::from(be32(co, c * 4)?)
        };
        let n = per.min(len - sample);
        let bytes = sizes.sum(sample as usize, (sample + n) as usize);
        if n > 0 && off.checked_add(bytes).is_none_or(|end| end > file_size) {
            return Err(Mp4Error::Invalid("chunk (sample data outside the file)"));
        }
        first.push(sample);
        offs.push(off);
        sample += n;
        total += bytes;
    }
    if sample < len {
        return Err(Mp4Error::Invalid("stsc (samples outside every chunk)"));
    }
    if first.is_empty() {
        first.push(0);
        offs.push(0);
    }
    Ok((first, offs, total))
}
