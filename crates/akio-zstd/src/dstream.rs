//! The streaming decoder: frames fed in pieces, decoded a block at a time into a window that
//! slides.

use crate::decode::{Decoder, FrameHeader, Out, WILD, frame_header};
use crate::dict::Dictionary;
use crate::tables::{BLOCK_MAX, MAGIC, SKIPPABLE_MAGIC, SKIPPABLE_MASK};
use crate::xxhash::Xxh64;
use crate::{Error, Progress};

/// The default largest window a [`Decompressor`] accepts: 8 MiB, the limit RFC 9659 sets for
/// HTTP's `zstd` content coding and the size RFC 8878 recommends decoders to support.
pub const DEFAULT_MAX_WINDOW: usize = 8 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// Before a frame: its magic number is next.
    Magic,
    /// A Zstandard frame header (its first five bytes are in `inbuf`).
    Header,
    /// A skippable frame's size field.
    SkipSize,
    /// Inside a skippable frame: bytes left.
    Skip(u64),
    BlockHeader,
    /// A block of `kind` (0 raw, 1 RLE, 2 compressed) and `size`, the last of its frame or not.
    Block {
        kind: u8,
        size: usize,
        last: bool,
    },
    Checksum,
    Failed(Error),
}

/// The frame being decoded.
#[derive(Clone, Copy, Debug)]
struct Frame {
    window: usize,
    block_max: usize,
    content_size: Option<u64>,
    checksum: bool,
    /// Content decoded so far.
    produced: u64,
}

/// A streaming Zstandard decompressor: concatenated frames (skippable ones included) fed in
/// pieces of any size, with bounded memory.
///
/// It keeps the frame's window (at most [`max_window`](Decompressor::max_window), 8 MiB by
/// default; frames asking for more fail with [`Error::WindowTooLarge`]) plus up to the same
/// again before sliding it, one block of output and at most one block of input (128 KiB),
/// whatever the input says. [`decompress_vec`](Decompressor::decompress_vec) appends under a
/// size limit, the decompression-bomb defence. A frame naming a dictionary needs
/// [`with_dictionary`](Decompressor::with_dictionary) and the dictionary of that ID.
///
/// ```
/// use akio_zstd::{Decompressor, Level, compress};
///
/// let packed = compress(Level::DEFAULT, &b"hello zstd ".repeat(1000));
/// let mut d = Decompressor::new();
/// let mut out = Vec::new();
/// for piece in packed.chunks(7) {
///     d.decompress_vec(piece, &mut out, 1 << 20).unwrap();
/// }
/// assert!(d.is_done());
/// assert_eq!(out, b"hello zstd ".repeat(1000));
/// ```
pub struct Decompressor {
    dctx: Box<Decoder>,
    dict: Option<Dictionary>,
    max_window: usize,
    state: State,
    /// Header or block bytes gathered across calls.
    inbuf: Vec<u8>,
    /// The window: `win[..wpos]` is the history (the dictionary's content first), of which
    /// `win[flushed..wpos]` is not delivered yet.
    win: Vec<u8>,
    wpos: usize,
    flushed: usize,
    frame: Frame,
    hash: Xxh64,
    /// The input so far ends with a complete frame.
    at_end: bool,
    total_in: u64,
    total_out: u64,
}

impl std::fmt::Debug for Decompressor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Decompressor")
            .field("state", &self.state)
            .field("max_window", &self.max_window)
            .field("dictionary", &self.dict)
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

/// Appends input bytes to `inbuf` until it holds `n`; whether it does.
fn gather(inbuf: &mut Vec<u8>, input: &[u8], ip: &mut usize, n: usize) -> bool {
    if inbuf.len() < n {
        let take = (n - inbuf.len()).min(input.len() - *ip);
        inbuf.extend_from_slice(&input[*ip..*ip + take]);
        *ip += take;
    }
    inbuf.len() >= n
}

impl Decompressor {
    /// A decompressor without a dictionary and an 8 MiB window limit.
    pub fn new() -> Decompressor {
        Decompressor {
            dctx: Box::default(),
            dict: None,
            max_window: DEFAULT_MAX_WINDOW,
            state: State::Magic,
            inbuf: Vec::new(),
            win: Vec::new(),
            wpos: 0,
            flushed: 0,
            frame: Frame {
                window: 0,
                block_max: 0,
                content_size: None,
                checksum: false,
                produced: 0,
            },
            hash: Xxh64::new(0),
            at_end: false,
            total_in: 0,
            total_out: 0,
        }
    }

    /// A decompressor whose frames may use `dict`: those naming its Dictionary_ID, and those
    /// naming none (as libzstd does).
    pub fn with_dictionary(dict: &Dictionary) -> Decompressor {
        let mut d = Decompressor::new();
        d.dict = Some(dict.clone());
        d
    }

    /// Sets the largest window accepted (at least 1 KiB, at most 3.75 GiB). Memory is about
    /// twice the window plus 256 KiB.
    #[must_use]
    pub fn max_window(mut self, bytes: usize) -> Decompressor {
        self.max_window = bytes.clamp(1 << 10, 0xF000_0000);
        self
    }

    /// Forgets the current frame to decode a new stream; buffers are kept.
    pub fn reset(&mut self) {
        self.state = State::Magic;
        self.inbuf.clear();
        self.wpos = 0;
        self.flushed = 0;
        self.at_end = false;
        self.total_in = 0;
        self.total_out = 0;
    }

    /// The input so far ends with a complete frame (or skippable frame) and all of its output
    /// was delivered.
    pub fn is_done(&self) -> bool {
        self.at_end && self.flushed == self.wpos
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
    /// total. Returns when the input is used up (everything decodable from it delivered) or
    /// `out` reached `limit`; frames that follow each other are decoded in turn.
    ///
    /// For a size limit `max` on the decompressed data, pass `limit = max + 1`: `out.len() >
    /// max` afterwards means the data is too large. After an error the decompressor stays
    /// failed (every later call returns the same error) until [`reset`](Self::reset).
    pub fn decompress_vec(
        &mut self,
        input: &[u8],
        out: &mut Vec<u8>,
        limit: usize,
    ) -> Result<Progress, Error> {
        let start = out.len();
        let room = limit.saturating_sub(start);
        let r = self.run(input, room, &mut |b: &[u8]| out.extend_from_slice(b));
        r.map(|(consumed, done)| Progress {
            consumed,
            produced: out.len() - start,
            done,
        })
    }

    /// Decompresses `input` into `output`. Returns when `output` is full or the input is used
    /// up (everything decodable from it delivered): when `produced < output.len()` and not
    /// `done`, more input is needed.
    pub fn decompress(&mut self, input: &[u8], output: &mut [u8]) -> Result<Progress, Error> {
        let mut op = 0;
        let r = self.run(input, output.len(), &mut |b: &[u8]| {
            output[op..op + b.len()].copy_from_slice(b);
            op += b.len();
        });
        r.map(|(consumed, done)| Progress {
            consumed,
            produced: op,
            done,
        })
    }

    /// Delivers pending output (at most `*room` bytes) through `emit`.
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
    ) -> Result<(usize, bool), Error> {
        if let State::Failed(e) = self.state {
            return Err(e);
        }
        let mut ip = 0;
        let r = self.step(input, &mut ip, &mut room, emit);
        self.total_in += ip as u64;
        match r {
            Ok(()) => Ok((ip, self.is_done())),
            Err(e) => {
                self.state = State::Failed(e);
                Err(e)
            }
        }
    }

    fn step(
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
            match self.state {
                State::Magic => {
                    if *ip == input.len() {
                        return Ok(());
                    }
                    self.at_end = false;
                    if !gather(&mut self.inbuf, input, ip, 4) {
                        return Ok(());
                    }
                    let m = self.inbuf_le32(0);
                    if m & SKIPPABLE_MASK == SKIPPABLE_MAGIC {
                        self.state = State::SkipSize;
                    } else if m == MAGIC {
                        self.state = State::Header;
                    } else {
                        return Err(Error::BadMagic);
                    }
                }
                State::SkipSize => {
                    if !gather(&mut self.inbuf, input, ip, 8) {
                        return Ok(());
                    }
                    self.state = State::Skip(u64::from(self.inbuf_le32(4)));
                    self.inbuf.clear();
                }
                State::Skip(left) => {
                    let n = (left.min((input.len() - *ip) as u64)) as usize;
                    *ip += n;
                    if left > n as u64 {
                        self.state = State::Skip(left - n as u64);
                        return Ok(());
                    }
                    self.state = State::Magic;
                    self.at_end = true;
                }
                State::Header => {
                    // The header's size is known from its fifth byte.
                    if !gather(&mut self.inbuf, input, ip, 5) {
                        return Ok(());
                    }
                    let fhd = self.inbuf[4];
                    let single = fhd & 0x20 != 0;
                    let size = 5
                        + usize::from(!single)
                        + [0, 1, 2, 4][usize::from(fhd & 3)]
                        + [usize::from(single), 2, 4, 8][usize::from(fhd >> 6)];
                    if !gather(&mut self.inbuf, input, ip, size) {
                        return Ok(());
                    }
                    let Some(h) = frame_header(&self.inbuf)? else {
                        return Err(Error::Truncated); // unreachable: all of it is there
                    };
                    self.inbuf.clear();
                    self.start_frame(h)?;
                    self.state = State::BlockHeader;
                }
                State::BlockHeader => {
                    if !gather(&mut self.inbuf, input, ip, 3) {
                        return Ok(());
                    }
                    let bh = u32::from_le_bytes([self.inbuf[0], self.inbuf[1], self.inbuf[2], 0]);
                    self.inbuf.clear();
                    let size = (bh >> 3) as usize;
                    let kind = ((bh >> 1) & 3) as u8;
                    if kind == 3 || size > self.frame.block_max {
                        return Err(Error::BadBlock);
                    }
                    self.state = State::Block {
                        kind,
                        size,
                        last: bh & 1 == 1,
                    };
                }
                State::Block { kind, size, last } => {
                    let need = if kind == 1 { 1 } else { size };
                    // The block straight from the input when all of it is there, else
                    // gathered.
                    let direct = self.inbuf.is_empty() && input.len() - *ip >= need;
                    let mut inbuf = std::mem::take(&mut self.inbuf);
                    let src: &[u8] = if direct {
                        let s = &input[*ip..*ip + need];
                        *ip += need;
                        s
                    } else if gather(&mut inbuf, input, ip, need) {
                        &inbuf
                    } else {
                        self.inbuf = inbuf;
                        return Ok(());
                    };
                    let r = self.block(kind, size, src);
                    inbuf.clear();
                    self.inbuf = inbuf;
                    r?;
                    self.state = if !last {
                        State::BlockHeader
                    } else {
                        if let Some(n) = self.frame.content_size {
                            if self.frame.produced != n {
                                return Err(Error::ContentSizeMismatch);
                            }
                        }
                        if self.frame.checksum {
                            State::Checksum
                        } else {
                            self.at_end = true;
                            State::Magic
                        }
                    };
                }
                State::Checksum => {
                    if !gather(&mut self.inbuf, input, ip, 4) {
                        return Ok(());
                    }
                    if self.hash.digest() as u32 != self.inbuf_le32(0) {
                        return Err(Error::ChecksumMismatch);
                    }
                    self.inbuf.clear();
                    self.at_end = true;
                    self.state = State::Magic;
                }
                State::Failed(e) => return Err(e),
            }
        }
    }

    fn inbuf_le32(&self, at: usize) -> u32 {
        let b = &self.inbuf[at..at + 4];
        u32::from_le_bytes([b[0], b[1], b[2], b[3]])
    }

    /// Sets up the window and the decoder for the frame of header `h`.
    fn start_frame(&mut self, h: FrameHeader) -> Result<(), Error> {
        if h.window > self.max_window as u64 {
            return Err(Error::WindowTooLarge);
        }
        let dict = match (&self.dict, h.dict_id) {
            (Some(d), 0) => Some(d),
            (Some(d), id) if d.id() == id => Some(d),
            (Some(_), _) => return Err(Error::WrongDictionary),
            (None, 0) => None,
            (None, _) => return Err(Error::DictionaryRequired),
        };
        let window = h.window as usize;
        self.frame = Frame {
            window,
            block_max: window.min(BLOCK_MAX),
            content_size: h.content_size,
            checksum: h.checksum,
            produced: 0,
        };
        // Everything earlier was delivered (decoding stops while output is pending).
        self.win.clear();
        self.wpos = 0;
        if let Some(d) = dict {
            self.win.extend_from_slice(d.content());
            self.wpos = self.win.len();
        }
        self.flushed = self.wpos;
        self.dctx
            .start_frame(dict.and_then(|d| d.0.entropy.as_ref()).map(|e| &e.dtables));
        self.hash = Xxh64::new(0);
        Ok(())
    }

    /// Decodes a block of `kind` and `size` whose bytes (one for RLE) are `src`.
    fn block(&mut self, kind: u8, size: usize, src: &[u8]) -> Result<(), Error> {
        let f = self.frame;
        let n = if kind == 2 { f.block_max } else { size };
        // Slide: keep the window, once the dictionary (if any) is out of reach (the encoder
        // refers to it only while the frame's content is shorter than the window).
        if self.wpos >= f.window + f.window.max(BLOCK_MAX) && f.produced >= f.window as u64 {
            let drop = self.wpos - f.window;
            self.win.copy_within(drop..self.wpos, 0);
            self.wpos -= drop;
            self.flushed = self.wpos;
        }
        let need = self.wpos + n + WILD;
        if self.win.capacity() < need {
            let cap_max = 2 * f.window.max(BLOCK_MAX) + self.wpos.min(1 << 30) + BLOCK_MAX + WILD;
            let cap = (self.win.capacity() * 2).clamp(need, need.max(cap_max));
            self.win.reserve_exact(cap - self.win.len());
        }
        let start = self.wpos;
        match kind {
            0 => {
                self.win.truncate(start);
                self.win.extend_from_slice(src);
                self.wpos += size;
            }
            1 => {
                self.win.truncate(start);
                self.win.resize(start + size, src[0]);
                self.wpos += size;
            }
            _ => {
                let mut out = Out {
                    buf: std::mem::take(&mut self.win),
                    pos: start,
                    limit: start + f.block_max + WILD,
                };
                let r = self.dctx.block(src, &mut out, 0, f.block_max);
                self.win = out.buf;
                r?;
                self.wpos = out.pos;
            }
        }
        let made = self.wpos - start;
        self.frame.produced += made as u64;
        if let Some(cs) = f.content_size {
            if self.frame.produced > cs {
                return Err(Error::ContentSizeMismatch);
            }
        }
        if f.checksum {
            self.hash.update(&self.win[start..self.wpos]);
        }
        Ok(())
    }
}

/// Decompresses `data` (one or more frames) with `dict` into at most `limit` bytes, like
/// [`decompress`](crate::decompress): frames naming the dictionary's ID or none may use it.
/// The window limit is the frames' own (there is no streaming here), up to 3.75 GiB.
pub fn decompress_with_dictionary(
    data: &[u8],
    limit: usize,
    dict: &Dictionary,
) -> Result<Vec<u8>, Error> {
    let mut d = Decompressor::with_dictionary(dict).max_window(usize::MAX);
    let mut out = Vec::new();
    let p = d.decompress_vec(data, &mut out, limit.saturating_add(1))?;
    if out.len() > limit {
        return Err(Error::TooLarge);
    }
    if data.is_empty() || (p.done && p.consumed == data.len()) {
        Ok(out)
    } else {
        Err(Error::Truncated)
    }
}
