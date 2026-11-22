//! The streaming encoder: input taken in pieces, compressed a block at a time over a window
//! that slides.

use crate::dict::Dictionary;
use crate::encode::{Encoder, MAX_WINDOW, State, compress_impl, frame_header};
use crate::tables::BLOCK_MAX;
use crate::xxhash::Xxh64;
use crate::{Flush, Level};

/// A streaming Zstandard compressor: one frame, input taken in pieces of any size.
///
/// Input is compressed a block (128 KiB, or the window if smaller) at a time, so output lags
/// input until a block fills up or [`Flush::Flush`] / [`Flush::Finish`] asks for everything.
/// The frame has a window of `2^window_log` bytes (by level from 512 KiB at level 1 to 8 MiB
/// from level 16, or [`window_log`](Compressor::window_log)), no Frame_Content_Size and a
/// content checksum; when the whole input arrives before anything is written (`Finish` on the
/// first call that has data, or after only [`Flush::None`] calls of less than a block), the
/// frame is the one [`compress`](crate::compress) writes, with its content size. Memory is
/// the window up to about three times over, the match finder's tables and a block.
///
/// ```
/// use akio_zstd::{Compressor, Flush, Level, decompress};
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
    window_log: u32,
    dict: Option<Dictionary>,
    st: Option<State>,
    /// The dictionary's content, then the input: `buf[..pos]` is compressed (the part that
    /// is still in the window), `buf[pos..]` waits.
    buf: Vec<u8>,
    pos: usize,
    /// Content bytes compressed into blocks.
    produced: u64,
    started: bool,
    finished: bool,
    hash: Xxh64,
    total_in: u64,
}

impl std::fmt::Debug for Compressor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Compressor")
            .field("level", &self.level)
            .field("window_log", &self.window_log)
            .field("dictionary", &self.dict)
            .field("total_in", &self.total_in)
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

/// The window of a streamed frame by level (libzstd's for inputs of unknown size, up to the
/// 8 MiB of RFC 9659).
fn level_window_log(level: Level) -> u32 {
    match level.get() {
        1 | 2 => 19,
        3..=8 => 21,
        9..=15 => 22,
        _ => 23,
    }
}

impl Compressor {
    /// A compressor at `level` without a dictionary.
    pub fn new(level: Level) -> Compressor {
        Compressor {
            level,
            window_log: level_window_log(level),
            dict: None,
            st: None,
            buf: Vec::new(),
            pos: 0,
            produced: 0,
            started: false,
            finished: false,
            hash: Xxh64::new(0),
            total_in: 0,
        }
    }

    /// A compressor at `level` with `dict` (see
    /// [`compress_with_dictionary`](crate::compress_with_dictionary)).
    pub fn with_dictionary(level: Level, dict: &Dictionary) -> Compressor {
        let mut c = Compressor::new(level);
        c.dict = Some(dict.clone());
        c.reset();
        c
    }

    /// Sets the window to `2^log` bytes (`log` clamped to 10..=23), for a peer that decodes
    /// with less memory or to keep less per stream. Before the first input only.
    #[must_use]
    pub fn window_log(mut self, log: u32) -> Compressor {
        self.window_log = log.clamp(10, 23);
        self
    }

    /// Starts a new frame: the input so far is forgotten.
    pub fn reset(&mut self) {
        self.st = None;
        self.buf.clear();
        if let Some(d) = &self.dict {
            self.buf.extend_from_slice(d.content());
        }
        self.pos = self.buf.len();
        self.produced = 0;
        self.started = false;
        self.finished = false;
        self.hash = Xxh64::new(0);
        self.total_in = 0;
    }

    /// Input bytes taken since the last reset.
    pub fn total_in(&self) -> u64 {
        self.total_in
    }

    /// The frame was ended with [`Flush::Finish`]; further input is ignored until
    /// [`reset`](Compressor::reset).
    pub fn is_finished(&self) -> bool {
        self.finished
    }

    fn window(&self) -> usize {
        1 << self.window_log
    }

    fn block_size(&self) -> usize {
        BLOCK_MAX.min(self.window())
    }

    /// Compresses all of `input`, appending output to `out`, then applies `flush`.
    pub fn compress(&mut self, input: &[u8], out: &mut Vec<u8>, flush: Flush) {
        if self.finished {
            return;
        }
        self.buf.extend_from_slice(input);
        self.hash.update(input);
        self.total_in += input.len() as u64;
        let bs = self.block_size();
        loop {
            let pending = self.buf.len() - self.pos;
            if pending > bs || (pending == bs && flush != Flush::Finish) {
                self.block(self.pos + bs, false, out);
            } else {
                break;
            }
        }
        match flush {
            Flush::None => {}
            Flush::Flush => {
                if self.buf.len() > self.pos {
                    self.block(self.buf.len(), false, out);
                }
            }
            Flush::Finish => {
                if self.started {
                    self.block(self.buf.len(), true, out);
                    out.extend_from_slice(&(self.hash.digest() as u32).to_le_bytes());
                } else {
                    // Everything is here: the one-shot frame, with its content size.
                    let base = self.dict.as_ref().map_or(0, |d| d.content().len());
                    out.extend_from_slice(&compress_impl(
                        self.level,
                        &self.buf[base..],
                        self.dict.as_ref(),
                    ));
                }
                self.finished = true;
                self.st = None;
                self.buf = Vec::new();
                self.pos = 0;
            }
        }
    }

    /// Compresses `buf[pos..end]` as one block.
    fn block(&mut self, end: usize, last: bool, out: &mut Vec<u8>) {
        let window = self.window();
        let dict_len = self.dict.as_ref().map_or(0, |d| d.content().len());
        let mut st = match self.st.take() {
            Some(st) => st,
            None => {
                self.started = true;
                frame_header(
                    out,
                    None,
                    Some(self.window_log),
                    self.dict.as_ref().map_or(0, Dictionary::id),
                );
                let st = State::new(self.level, window.min(MAX_WINDOW), window + BLOCK_MAX);
                match &self.dict {
                    Some(d) => {
                        let mut e = Encoder::resume(&self.buf, st);
                        e.load_dictionary(d);
                        e.suspend()
                    }
                    None => st,
                }
            }
        };
        // Slide: keep the window behind `pos` (and the dictionary while the frame is within
        // its window, when the decoder still holds it).
        let mut end = end;
        if self.pos > window + window.max(BLOCK_MAX) && self.produced >= window as u64 {
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
        if dict_len > 0 {
            e.dict_window(
                (self.produced as usize).saturating_add(end - self.pos),
                window,
            );
        } else {
            e.set_window(window);
        }
        e.block(self.pos, end, last, out);
        self.st = Some(e.suspend());
        self.produced += (end - self.pos) as u64;
        self.pos = end;
    }
}
