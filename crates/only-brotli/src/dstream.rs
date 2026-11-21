//! The streaming decoder: a brotli stream fed in pieces, decoded by the one-shot decoder's
//! pieces resumed at unit boundaries (a header unit, a command), into a window that slides.

use std::sync::Arc;

use crate::bits::BitReader;
use crate::decode::{Decoder, HeaderBuild, Meta, MetaHead, Run};
use crate::huffman::Lengths;
use crate::{Error, Progress};

/// Output decoded ahead of delivery at most (then the command loop pauses).
const PAUSE: usize = 1 << 20;

/// Input appended to the internal buffer at a time when a unit spans calls.
const CHUNK: usize = 64 << 10;

/// The decoder's output limit (unused: output is bounded by pausing).
const NO_LIMIT: usize = usize::MAX >> 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    WindowBits,
    MetaHead,
    Metadata {
        left: usize,
        last: bool,
    },
    Uncompressed {
        left: usize,
    },
    Header {
        len: usize,
        last: bool,
    },
    Commands {
        last: bool,
    },
    /// After the last meta-block: the padding bits.
    End,
    Done,
    Failed(Error),
}

/// Why a step stopped.
enum Stop {
    /// More input is needed.
    Input,
    /// Output was produced (deliver it before going on), or the stream ended.
    Output,
}

/// A streaming brotli decompressor: one stream fed in pieces of any size, with bounded memory.
///
/// It decodes with the same code as [`decompress`](crate::decompress), resumed where the input
/// ran out at the last complete unit: a command, or a part of a meta-block header (a block type
/// description, a context map entry, a prefix code); a piece of input that ends inside a
/// unit is kept until the unit is complete, so input split anywhere costs little more than
/// whole input. Memory is the window (up to 16 MiB, `2^window_bits`; streams asking for more
/// than [`max_window_bits`](Decompressor::max_window_bits) fail with
/// [`Error::WindowTooLarge`]) up to twice over, about 1 MiB of output decoded ahead, the
/// meta-block's prefix codes and the input of one unit.
/// [`decompress_vec`](Decompressor::decompress_vec) appends under a size limit, the
/// decompression-bomb defence.
///
/// ```
/// use only_brotli::{Decompressor, Level, compress};
///
/// let packed = compress(Level::DEFAULT, &b"hello brotli ".repeat(1000));
/// let mut d = Decompressor::new();
/// let mut out = Vec::new();
/// for piece in packed.chunks(5) {
///     d.decompress_vec(piece, &mut out, 1 << 20).unwrap();
/// }
/// assert!(d.is_done());
/// assert_eq!(out, b"hello brotli ".repeat(1000));
/// ```
pub struct Decompressor {
    dict: Option<Arc<[u8]>>,
    max_window_bits: u32,
    state: State,
    /// Input bytes kept across calls; `bit` bits of them are consumed.
    inbuf: Vec<u8>,
    bit: u64,
    /// The window: `win[..wpos]` (stream position `base` at `win[0]`), of which
    /// `win[flushed..wpos]` is not delivered yet.
    win: Vec<u8>,
    wpos: usize,
    flushed: usize,
    base: usize,
    last: [usize; 4],
    lens: Lengths,
    max_backward: usize,
    header: HeaderBuild,
    meta: Meta,
    /// Bytes left in the current compressed meta-block.
    meta_left: usize,
    total_in: u64,
    total_out: u64,
}

impl std::fmt::Debug for Decompressor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Decompressor")
            .field("state", &self.state)
            .field("max_window_bits", &self.max_window_bits)
            .field("dictionary_len", &self.dict.as_ref().map(|d| d.len()))
            .field("total_in", &self.total_in)
            .field("total_out", &self.total_out)
            .finish_non_exhaustive()
    }
}

impl Default for Decompressor {
    fn default() -> Self {
        Self::new()
    }
}

impl Decompressor {
    /// A decompressor without a dictionary that accepts every window size (up to 16 MiB).
    pub fn new() -> Decompressor {
        Decompressor {
            dict: None,
            max_window_bits: 24,
            state: State::WindowBits,
            inbuf: Vec::new(),
            bit: 0,
            win: Vec::new(),
            wpos: 0,
            flushed: 0,
            base: 0,
            last: [4, 11, 15, 16],
            lens: Lengths::default(),
            max_backward: 0,
            header: HeaderBuild::default(),
            meta: Meta::default(),
            meta_left: 0,
            total_in: 0,
            total_out: 0,
        }
    }

    /// A decompressor with the raw (LZ77 prefix) dictionary `dict` (see
    /// [`decompress_with_dictionary`](crate::decompress_with_dictionary)).
    pub fn with_dictionary(dict: &[u8]) -> Decompressor {
        let mut d = Decompressor::new();
        d.dict = Some(Arc::from(dict));
        d
    }

    /// Refuses streams whose window is larger than `2^bits` bytes (`bits` clamped to
    /// 10..=24), to bound memory.
    #[must_use]
    pub fn max_window_bits(mut self, bits: u32) -> Decompressor {
        self.max_window_bits = bits.clamp(10, 24);
        self
    }

    /// Forgets the current stream to decode a new one; buffers are kept.
    pub fn reset(&mut self) {
        self.state = State::WindowBits;
        self.inbuf.clear();
        self.bit = 0;
        self.wpos = 0;
        self.flushed = 0;
        self.base = 0;
        self.last = [4, 11, 15, 16];
        self.header = HeaderBuild::default();
        self.meta = Meta::default();
        self.meta_left = 0;
        self.total_in = 0;
        self.total_out = 0;
    }

    /// The stream ended and all of its output was delivered.
    pub fn is_done(&self) -> bool {
        self.state == State::Done && self.flushed == self.wpos
    }

    /// Input bytes consumed since the last reset.
    pub fn total_in(&self) -> u64 {
        self.total_in
    }

    /// Output bytes delivered since the last reset.
    pub fn total_out(&self) -> u64 {
        self.total_out
    }

    /// Decompresses `input`, appending to `out` but never growing it past `limit` bytes in
    /// total. Returns when the input is used up (everything decodable from it delivered), the
    /// stream ended, or `out` reached `limit`.
    ///
    /// For a size limit `max` on the decompressed data, pass `limit = max + 1`: `out.len() >
    /// max` afterwards means the data is too large. Bytes after the end of the stream are an
    /// error ([`Error::TrailingData`]). After an error the decompressor stays failed (every
    /// later call returns the same error) until [`reset`](Self::reset).
    pub fn decompress_vec(
        &mut self,
        input: &[u8],
        out: &mut Vec<u8>,
        limit: usize,
    ) -> Result<Progress, Error> {
        let start = out.len();
        let room = limit.saturating_sub(start);
        let r = self.run(input, room, &mut |b: &[u8]| out.extend_from_slice(b));
        r.map(|consumed| Progress {
            consumed,
            produced: out.len() - start,
            done: self.is_done(),
        })
    }

    /// Decompresses `input` into `output`. Returns when `output` is full, the input is used
    /// up (everything decodable from it delivered) or the stream ended: when `produced <
    /// output.len()` and not `done`, more input is needed.
    pub fn decompress(&mut self, input: &[u8], output: &mut [u8]) -> Result<Progress, Error> {
        let mut op = 0;
        let r = self.run(input, output.len(), &mut |b: &[u8]| {
            output[op..op + b.len()].copy_from_slice(b);
            op += b.len();
        });
        r.map(|consumed| Progress {
            consumed,
            produced: op,
            done: self.is_done(),
        })
    }

    fn deliver(&mut self, room: &mut usize, emit: &mut dyn FnMut(&[u8])) {
        let n = (self.wpos - self.flushed).min(*room);
        if n > 0 {
            emit(&self.win[self.flushed..self.flushed + n]);
            self.flushed += n;
            *room -= n;
            self.total_out += n as u64;
        }
    }

    fn run(
        &mut self,
        input: &[u8],
        mut room: usize,
        emit: &mut dyn FnMut(&[u8]),
    ) -> Result<usize, Error> {
        if let State::Failed(e) = self.state {
            return Err(e);
        }
        let mut ip = 0;
        let r = self.drive(input, &mut ip, &mut room, emit);
        self.total_in += ip as u64;
        match r {
            Ok(()) => Ok(ip),
            Err(e) => {
                self.state = State::Failed(e);
                Err(e)
            }
        }
    }

    fn drive(
        &mut self,
        input: &[u8],
        ip: &mut usize,
        room: &mut usize,
        emit: &mut dyn FnMut(&[u8]),
    ) -> Result<(), Error> {
        loop {
            self.deliver(room, emit);
            if self.flushed < self.wpos {
                return Ok(()); // the output is full
            }
            if self.state == State::Done {
                if *ip < input.len() || !self.inbuf.is_empty() {
                    return Err(Error::TrailingData);
                }
                return Ok(());
            }
            self.slide();
            let stop = if self.inbuf.is_empty() {
                // Straight from the caller's input; what a unit leaves unfinished is kept.
                let data = &input[*ip..];
                if data.is_empty() && self.state != State::End {
                    return Ok(());
                }
                let stop = self.step(data)?;
                let used = (self.bit / 8) as usize;
                *ip += used;
                self.bit -= 8 * used as u64;
                if let Stop::Input = stop {
                    self.inbuf.extend_from_slice(&input[*ip..]);
                    *ip = input.len();
                }
                stop
            } else {
                let take = CHUNK.min(input.len() - *ip);
                let more = take > 0;
                self.inbuf.extend_from_slice(&input[*ip..*ip + take]);
                *ip += take;
                let mut inbuf = std::mem::take(&mut self.inbuf);
                let r = self.step(&inbuf);
                let used = ((self.bit / 8) as usize).min(inbuf.len());
                inbuf.drain(..used);
                self.bit -= 8 * used as u64;
                self.inbuf = inbuf;
                match r? {
                    Stop::Input if !more => return Ok(()),
                    s => s,
                }
            };
            if let Stop::Input = stop {
                if *ip == input.len() {
                    return Ok(());
                }
            }
        }
    }

    /// Drops history beyond the window once it is large enough to be worth moving.
    fn slide(&mut self) {
        let keep = self.max_backward + 16;
        if self.max_backward > 0 && self.wpos >= keep + keep.max(PAUSE) {
            let drop = self.wpos - keep;
            self.win.copy_within(drop..self.wpos, 0);
            self.wpos -= drop;
            self.flushed -= drop;
            self.base += drop;
        }
    }

    /// Runs the state machine over `data` from bit `self.bit` until it needs more input or
    /// has output to deliver; `self.bit` is left at the last complete unit.
    fn step(&mut self, data: &[u8]) -> Result<Stop, Error> {
        let dict = self.dict.clone();
        let mut d = Decoder::new(
            BitReader::at(data, self.bit),
            std::mem::take(&mut self.win),
            self.wpos,
            NO_LIMIT,
            dict.as_deref().unwrap_or(&[]),
        );
        d.base = self.base;
        d.last = self.last;
        d.lens = std::mem::take(&mut self.lens);
        let r = self.step_with(&mut d, data);
        self.bit = d.br.bit_pos();
        self.win = d.buf;
        self.wpos = d.pos;
        self.last = d.last;
        self.lens = d.lens;
        r
    }

    fn step_with<'a>(&mut self, d: &mut Decoder<'a, '_>, data: &'a [u8]) -> Result<Stop, Error> {
        loop {
            let cp = d.br;
            match self.state {
                State::WindowBits => {
                    let r = d.window_bits();
                    if d.br.overrun() {
                        d.br = cp;
                        return Ok(Stop::Input);
                    }
                    let w = r?;
                    if w > self.max_window_bits {
                        return Err(Error::WindowTooLarge);
                    }
                    self.max_backward = (1usize << w) - 16;
                    self.state = State::MetaHead;
                }
                State::MetaHead => {
                    let r = d.meta_head();
                    if d.br.overrun() {
                        d.br = cp;
                        return Ok(Stop::Input);
                    }
                    self.state = match r? {
                        MetaHead::LastEmpty => State::End,
                        MetaHead::Metadata { len, last } => State::Metadata { left: len, last },
                        MetaHead::Uncompressed { len } => State::Uncompressed { left: len },
                        MetaHead::Compressed { len, last } => {
                            self.header = HeaderBuild::default();
                            State::Header { len, last }
                        }
                    };
                }
                State::Metadata { left, .. } | State::Uncompressed { left } => {
                    // Byte-aligned here.
                    let at = (d.br.bit_pos() / 8) as usize;
                    let n = left.min(data.len().saturating_sub(at)).min(PAUSE);
                    let uncompressed = matches!(self.state, State::Uncompressed { .. });
                    let last = matches!(self.state, State::Metadata { last: true, .. });
                    if uncompressed {
                        d.extend(&data[at..at + n]);
                    }
                    d.br = BitReader::at(data, 8 * (at + n) as u64);
                    let left = left - n;
                    self.state = if left > 0 && uncompressed {
                        State::Uncompressed { left }
                    } else if left > 0 {
                        State::Metadata { left, last }
                    } else if last {
                        State::End
                    } else {
                        State::MetaHead
                    };
                    if left > 0 && n == 0 {
                        return Ok(Stop::Input);
                    }
                    if uncompressed && n > 0 {
                        return Ok(Stop::Output);
                    }
                }
                State::Header { len, last } => match d.header::<true>(&mut self.header)? {
                    Some(m) => {
                        self.meta = m;
                        self.meta_left = len;
                        self.state = State::Commands { last };
                    }
                    None => return Ok(Stop::Input),
                },
                State::Commands { last } => {
                    let end = d.pos + self.meta_left;
                    let run =
                        d.commands::<true>(&mut self.meta, end, self.max_backward, d.pos + PAUSE)?;
                    self.meta_left = end - d.pos;
                    match run {
                        Run::Done => {
                            self.meta = Meta::default();
                            self.state = if last { State::End } else { State::MetaHead };
                            return Ok(Stop::Output);
                        }
                        Run::Paused => return Ok(Stop::Output),
                        Run::Suspended => return Ok(Stop::Input),
                    }
                }
                State::End => {
                    if !d.br.align() {
                        return Err(Error::BadPadding);
                    }
                    self.state = State::Done;
                    let at = (d.br.bit_pos() / 8) as usize;
                    if at < data.len() {
                        return Err(Error::TrailingData);
                    }
                    return Ok(Stop::Output);
                }
                State::Done => return Ok(Stop::Output),
                State::Failed(e) => return Err(e),
            }
        }
    }
}
