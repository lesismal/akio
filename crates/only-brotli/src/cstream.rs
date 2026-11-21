//! The streaming encoder: input taken in pieces, compressed a meta-block at a time over a
//! window that slides.

use std::sync::Arc;

use crate::bits::BitWriter;
use crate::encode::{Encoder, State, compress_impl, write_window_bits};
use crate::{Flush, Level};

/// A streaming brotli compressor: one stream, input taken in pieces of any size.
///
/// Input is compressed a meta-block at a time (1 MiB, 256 KiB at levels 10 and 11), so output
/// lags input until a meta-block fills up or [`Flush::Flush`] / [`Flush::Finish`] asks for
/// everything: `Flush` ends the meta-block and pads to a byte boundary with an empty metadata
/// block, as Google's encoder does for `BROTLI_OPERATION_FLUSH`. The window is `2^22` bytes
/// (Google's default) unless set with [`window_bits`](Compressor::window_bits); when the
/// whole input arrives before anything is written, the stream is the one
/// [`compress`](crate::compress) writes. Memory is the window up to about three times over,
/// a meta-block and the match finder's tables.
///
/// ```
/// use only_brotli::{Compressor, Flush, Level, decompress};
///
/// let mut c = Compressor::new(Level::DEFAULT);
/// let mut wire = Vec::new();
/// c.compress(b"event: one\n\n", &mut wire, Flush::Flush);
/// let first = wire.len(); // a decoder can produce the first event from these bytes
/// c.compress(b"event: two\n\n", &mut wire, Flush::Finish);
/// assert!(first > 0);
/// assert_eq!(decompress(&wire, 1 << 10).unwrap(), b"event: one\n\nevent: two\n\n");
/// ```
pub struct Compressor {
    level: Level,
    wbits: u32,
    dict: Option<Arc<[u8]>>,
    st: Option<State>,
    w: BitWriter,
    /// The dictionary, then the input: `buf[..pos]` is compressed (as far as it is still in
    /// the window), `buf[pos..]` waits.
    buf: Vec<u8>,
    pos: usize,
    /// Stream bytes compressed into meta-blocks.
    produced: u64,
    started: bool,
    finished: bool,
    total_in: u64,
}

impl std::fmt::Debug for Compressor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Compressor")
            .field("level", &self.level)
            .field("window_bits", &self.wbits)
            .field("dictionary_len", &self.dict.as_ref().map(|d| d.len()))
            .field("total_in", &self.total_in)
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

impl Compressor {
    /// A compressor at `level` without a dictionary.
    pub fn new(level: Level) -> Compressor {
        Compressor {
            level,
            wbits: 22,
            dict: None,
            st: None,
            w: BitWriter::with_capacity(0),
            buf: Vec::new(),
            pos: 0,
            produced: 0,
            started: false,
            finished: false,
            total_in: 0,
        }
    }

    /// A compressor at `level` with the raw dictionary `dict` (see
    /// [`compress_with_dictionary`](crate::compress_with_dictionary)).
    pub fn with_dictionary(level: Level, dict: &[u8]) -> Compressor {
        let mut c = Compressor::new(level);
        c.dict = Some(Arc::from(dict));
        c.reset();
        c
    }

    /// Sets the window to `2^bits` bytes (`bits` clamped to 10..=24), for a decoder with
    /// less memory or to keep less per stream. Before the first input only.
    #[must_use]
    pub fn window_bits(mut self, bits: u32) -> Compressor {
        self.wbits = bits.clamp(10, 24);
        self
    }

    /// Starts a new stream: the input so far is forgotten.
    pub fn reset(&mut self) {
        self.st = None;
        self.w = BitWriter::with_capacity(0);
        self.buf.clear();
        if let Some(d) = &self.dict {
            self.buf.extend_from_slice(d);
        }
        self.pos = self.buf.len();
        self.produced = 0;
        self.started = false;
        self.finished = false;
        self.total_in = 0;
    }

    /// Input bytes taken since the last reset.
    pub fn total_in(&self) -> u64 {
        self.total_in
    }

    /// The stream was ended with [`Flush::Finish`]; further input is ignored until
    /// [`reset`](Compressor::reset).
    pub fn is_finished(&self) -> bool {
        self.finished
    }

    fn dict_len(&self) -> usize {
        self.dict.as_ref().map_or(0, |d| d.len())
    }

    /// Compresses all of `input`, appending output to `out`, then applies `flush`.
    pub fn compress(&mut self, input: &[u8], out: &mut Vec<u8>, flush: Flush) {
        if self.finished {
            return;
        }
        self.buf.extend_from_slice(input);
        self.total_in += input.len() as u64;
        let block = self.block_size();
        loop {
            let pending = self.buf.len() - self.pos;
            if pending > block || (pending == block && flush != Flush::Finish) {
                self.meta_block(self.pos + block, false);
            } else {
                break;
            }
        }
        match flush {
            Flush::None => {}
            Flush::Flush => {
                if self.buf.len() > self.pos {
                    self.meta_block(self.buf.len(), false);
                }
                if self.started && self.w.bit_len() % 8 != 0 {
                    // An empty metadata block (ISLAST 0, MNIBBLES 11, reserved 0, MSKIPBYTES
                    // 00), then the padding to a byte boundary.
                    self.w.bits(6, 0b00_0110);
                }
                // Out of the accumulator too.
                self.w.align();
            }
            Flush::Finish => {
                if self.started {
                    if self.buf.len() > self.pos {
                        self.meta_block(self.buf.len(), true);
                    } else {
                        self.w.bits(2, 0b11); // ISLAST, ISLASTEMPTY
                    }
                    self.w.align();
                } else {
                    // Everything is here: the one-shot stream.
                    let d = self.dict_len();
                    let dict = self.dict.clone();
                    out.extend_from_slice(&compress_impl(
                        self.level,
                        &self.buf[d..],
                        dict.as_deref().unwrap_or(&[]),
                    ));
                }
                self.finished = true;
                self.st = None;
                self.buf = Vec::new();
                self.pos = 0;
            }
        }
        self.w.drain_into(out);
    }

    fn block_size(&self) -> usize {
        match self.level.get() {
            10 | 11 => 1 << 18,
            _ => 1 << 20,
        }
    }

    /// Compresses `buf[pos..end]` as one meta-block.
    fn meta_block(&mut self, end: usize, last: bool) {
        let window = 1usize << self.wbits;
        let dict_len = self.dict_len();
        let mut st = match self.st.take() {
            Some(st) => st,
            None => {
                self.started = true;
                write_window_bits(&mut self.w, self.wbits);
                let st = Encoder::state(self.level, self.wbits, dict_len);
                if dict_len > 0 {
                    let mut e = Encoder::resume(&self.buf, st);
                    e.insert_until(dict_len);
                    e.suspend()
                } else {
                    st
                }
            }
        };
        debug_assert_eq!(st.block(), self.block_size());
        // Slide: keep the window behind `pos`, once the dictionary is out of reach. Sliding
        // once the buffer holds two windows (not a window plus a meta-block) keeps a stream
        // with a small window small; the copy is still amortized over a window of input.
        let mut end = end;
        if self.pos > 2 * window && self.produced >= window as u64 {
            let align = st.align();
            let drop = (self.pos - window) / align * align;
            if drop > 0 {
                self.buf.copy_within(drop.., 0);
                self.buf.truncate(self.buf.len() - drop);
                self.pos -= drop;
                end -= drop;
                st.rebase(drop);
            }
        }
        let mut e = Encoder::resume(&self.buf[..end], st);
        e.meta_block(&mut self.w, self.pos, end, last);
        self.st = Some(e.suspend());
        self.produced += (end - self.pos) as u64;
        self.pos = end;
    }
}
