//! HPACK (RFC 7541), header compression for HTTP/2: an [`Encoder`] and a [`Decoder`], each with
//! its dynamic table, and Huffman coding both ways.
//!
//! * The decoder enforces the limits of RFC 7541: indexes inside the tables, dynamic table size
//!   updates only at the start of a header block and never above the size we advertised
//!   ([`Decoder::set_max_allowed_table_size`]), integers that fit in 32 bits, Huffman strings
//!   without EOS and with at most 7 bits of all-ones padding. [`Decoder::decode_limited`] stops
//!   materializing fields past a header list size (the block is still processed, so the dynamic
//!   table stays in step with the peer).
//! * The encoder indexes fields (static table, then dynamic table; new fields are added to the
//!   dynamic table), sends credentials (`authorization`, `proxy-authorization`, short `cookie`s)
//!   as never-indexed literals, Huffman-codes strings when that is not longer
//!   ([`Encoder::set_huffman`]) and signals table size changes (RFC 7541 §4.2).
//! * Huffman decoding walks the code 4 bits at a time through a table built once; akio-h3's
//!   QPACK uses the same [`decode_huffman`].
//!
//! `#[doc(hidden)]`: not a public API, it may change in any release.

use std::collections::VecDeque;
use std::fmt;
use std::sync::OnceLock;

/// The HPACK Huffman code, `(code, bit length)` per symbol; 256 is EOS (RFC 7541 Appendix B).
#[rustfmt::skip]
const CODES: [(u32, u8); 257] = [
    (0x1ff8,13), (0x7fffd8,23), (0xfffffe2,28), (0xfffffe3,28), (0xfffffe4,28), (0xfffffe5,28), 
    (0xfffffe6,28), (0xfffffe7,28), (0xfffffe8,28), (0xffffea,24), (0x3ffffffc,30), (0xfffffe9,28), 
    (0xfffffea,28), (0x3ffffffd,30), (0xfffffeb,28), (0xfffffec,28), (0xfffffed,28), 
    (0xfffffee,28), (0xfffffef,28), (0xffffff0,28), (0xffffff1,28), (0xffffff2,28), 
    (0x3ffffffe,30), (0xffffff3,28), (0xffffff4,28), (0xffffff5,28), (0xffffff6,28), 
    (0xffffff7,28), (0xffffff8,28), (0xffffff9,28), (0xffffffa,28), (0xffffffb,28), (0x14,6), 
    (0x3f8,10), (0x3f9,10), (0xffa,12), (0x1ff9,13), (0x15,6), (0xf8,8), (0x7fa,11), (0x3fa,10), 
    (0x3fb,10), (0xf9,8), (0x7fb,11), (0xfa,8), (0x16,6), (0x17,6), (0x18,6), (0x0,5), (0x1,5), 
    (0x2,5), (0x19,6), (0x1a,6), (0x1b,6), (0x1c,6), (0x1d,6), (0x1e,6), (0x1f,6), (0x5c,7), 
    (0xfb,8), (0x7ffc,15), (0x20,6), (0xffb,12), (0x3fc,10), (0x1ffa,13), (0x21,6), (0x5d,7), 
    (0x5e,7), (0x5f,7), (0x60,7), (0x61,7), (0x62,7), (0x63,7), (0x64,7), (0x65,7), (0x66,7), 
    (0x67,7), (0x68,7), (0x69,7), (0x6a,7), (0x6b,7), (0x6c,7), (0x6d,7), (0x6e,7), (0x6f,7), 
    (0x70,7), (0x71,7), (0x72,7), (0xfc,8), (0x73,7), (0xfd,8), (0x1ffb,13), (0x7fff0,19), 
    (0x1ffc,13), (0x3ffc,14), (0x22,6), (0x7ffd,15), (0x3,5), (0x23,6), (0x4,5), (0x24,6), (0x5,5), 
    (0x25,6), (0x26,6), (0x27,6), (0x6,5), (0x74,7), (0x75,7), (0x28,6), (0x29,6), (0x2a,6), 
    (0x7,5), (0x2b,6), (0x76,7), (0x2c,6), (0x8,5), (0x9,5), (0x2d,6), (0x77,7), (0x78,7), 
    (0x79,7), (0x7a,7), (0x7b,7), (0x7ffe,15), (0x7fc,11), (0x3ffd,14), (0x1ffd,13), 
    (0xffffffc,28), (0xfffe6,20), (0x3fffd2,22), (0xfffe7,20), (0xfffe8,20), (0x3fffd3,22), 
    (0x3fffd4,22), (0x3fffd5,22), (0x7fffd9,23), (0x3fffd6,22), (0x7fffda,23), (0x7fffdb,23), 
    (0x7fffdc,23), (0x7fffdd,23), (0x7fffde,23), (0xffffeb,24), (0x7fffdf,23), (0xffffec,24), 
    (0xffffed,24), (0x3fffd7,22), (0x7fffe0,23), (0xffffee,24), (0x7fffe1,23), (0x7fffe2,23), 
    (0x7fffe3,23), (0x7fffe4,23), (0x1fffdc,21), (0x3fffd8,22), (0x7fffe5,23), (0x3fffd9,22), 
    (0x7fffe6,23), (0x7fffe7,23), (0xffffef,24), (0x3fffda,22), (0x1fffdd,21), (0xfffe9,20), 
    (0x3fffdb,22), (0x3fffdc,22), (0x7fffe8,23), (0x7fffe9,23), (0x1fffde,21), (0x7fffea,23), 
    (0x3fffdd,22), (0x3fffde,22), (0xfffff0,24), (0x1fffdf,21), (0x3fffdf,22), (0x7fffeb,23), 
    (0x7fffec,23), (0x1fffe0,21), (0x1fffe1,21), (0x3fffe0,22), (0x1fffe2,21), (0x7fffed,23), 
    (0x3fffe1,22), (0x7fffee,23), (0x7fffef,23), (0xfffea,20), (0x3fffe2,22), (0x3fffe3,22), 
    (0x3fffe4,22), (0x7ffff0,23), (0x3fffe5,22), (0x3fffe6,22), (0x7ffff1,23), (0x3ffffe0,26), 
    (0x3ffffe1,26), (0xfffeb,20), (0x7fff1,19), (0x3fffe7,22), (0x7ffff2,23), (0x3fffe8,22), 
    (0x1ffffec,25), (0x3ffffe2,26), (0x3ffffe3,26), (0x3ffffe4,26), (0x7ffffde,27), (0x7ffffdf,27), 
    (0x3ffffe5,26), (0xfffff1,24), (0x1ffffed,25), (0x7fff2,19), (0x1fffe3,21), (0x3ffffe6,26), 
    (0x7ffffe0,27), (0x7ffffe1,27), (0x3ffffe7,26), (0x7ffffe2,27), (0xfffff2,24), (0x1fffe4,21), 
    (0x1fffe5,21), (0x3ffffe8,26), (0x3ffffe9,26), (0xffffffd,28), (0x7ffffe3,27), (0x7ffffe4,27), 
    (0x7ffffe5,27), (0xfffec,20), (0xfffff3,24), (0xfffed,20), (0x1fffe6,21), (0x3fffe9,22), 
    (0x1fffe7,21), (0x1fffe8,21), (0x7ffff3,23), (0x3fffea,22), (0x3fffeb,22), (0x1ffffee,25), 
    (0x1ffffef,25), (0xfffff4,24), (0xfffff5,24), (0x3ffffea,26), (0x7ffff4,23), (0x3ffffeb,26), 
    (0x7ffffe6,27), (0x3ffffec,26), (0x3ffffed,26), (0x7ffffe7,27), (0x7ffffe8,27), (0x7ffffe9,27), 
    (0x7ffffea,27), (0x7ffffeb,27), (0xffffffe,28), (0x7ffffec,27), (0x7ffffed,27), (0x7ffffee,27), 
    (0x7ffffef,27), (0x7fffff0,27), (0x3ffffee,26), (0x3fffffff,30),
];

const EOS: u16 = 256;

/// Binary decoding tree: node `i` has children `tree[i][bit]`; a value `>= LEAF` is the leaf of
/// symbol `value - LEAF`, 0 is "no child" (the root is never a child).
const LEAF: u16 = 0x8000;

fn build_tree() -> Vec<[u16; 2]> {
    let mut t = vec![[0u16; 2]];
    for (sym, &(code, len)) in CODES.iter().enumerate() {
        let mut node = 0usize;
        for i in (0..len).rev() {
            let bit = ((code >> i) & 1) as usize;
            if i == 0 {
                t[node][bit] = LEAF | sym as u16;
            } else {
                if t[node][bit] == 0 {
                    t.push([0, 0]);
                    t[node][bit] = (t.len() - 1) as u16;
                }
                node = t[node][bit] as usize;
            }
        }
    }
    t
}

/// The decoding state machine: per internal tree node (256 of them, the root is 0) and input
/// nibble, the node reached plus the symbol completed on the way, if any (codes are at least
/// 5 bits long, so at most one per nibble).
struct Fsm {
    /// `next node | EMIT | FAIL | symbol << 16`, indexed by `node * 16 + nibble`.
    trans: Vec<u32>,
    /// Nodes where a string may end: reached from the root by at most 7 one-bits (padding).
    accept: Vec<bool>,
}

const EMIT: u32 = 0x100;
const FAIL: u32 = 0x200;

fn fsm() -> &'static Fsm {
    static FSM: OnceLock<Fsm> = OnceLock::new();
    FSM.get_or_init(|| {
        let t = build_tree();
        let mut trans = vec![0u32; t.len() * 16];
        for (s, slot) in trans.chunks_exact_mut(16).enumerate() {
            for (x, e) in slot.iter_mut().enumerate() {
                let (mut node, mut out) = (s, 0u32);
                for i in (0..4).rev() {
                    let next = t[node][(x >> i) & 1];
                    if next >= LEAF {
                        let sym = u32::from(next & !LEAF);
                        out |= if sym == u32::from(EOS) {
                            FAIL
                        } else {
                            EMIT | (sym << 16)
                        };
                        node = 0;
                    } else {
                        node = usize::from(next);
                    }
                }
                *e = out | node as u32;
            }
        }
        let mut accept = vec![false; t.len()];
        let mut node = 0usize;
        accept[0] = true;
        for _ in 0..7 {
            let next = t[node][1];
            if next >= LEAF {
                break;
            }
            node = usize::from(next);
            accept[node] = true;
        }
        Fsm { trans, accept }
    })
}

/// A Huffman-coded string that does not decode (see [`decode_huffman`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidHuffman;

/// Decodes a Huffman-coded string, appending to `out`. Fails on the EOS symbol, on padding longer
/// than 7 bits, and on padding that is not all ones (RFC 7541 §5.2).
pub fn decode_huffman(src: &[u8], out: &mut Vec<u8>) -> Result<(), InvalidHuffman> {
    let f = fsm();
    out.reserve(src.len() + src.len() / 2);
    let mut node = 0usize;
    for &byte in src {
        for x in [byte >> 4, byte & 0xf] {
            let e = f.trans[node * 16 + usize::from(x)];
            if e & FAIL != 0 {
                return Err(InvalidHuffman);
            }
            if e & EMIT != 0 {
                out.push((e >> 16) as u8);
            }
            node = (e & 0xff) as usize;
        }
    }
    if f.accept[node] {
        Ok(())
    } else {
        Err(InvalidHuffman)
    }
}

/// The length of `s` Huffman-coded.
pub fn huffman_len(s: &[u8]) -> usize {
    let bits: usize = s
        .iter()
        .map(|&c| usize::from(CODES[usize::from(c)].1))
        .sum();
    bits.div_ceil(8)
}

/// Huffman-codes `s`, appending to `out` (padded with ones, RFC 7541 §5.2).
pub fn encode_huffman(s: &[u8], out: &mut Vec<u8>) {
    let (mut acc, mut bits) = (0u64, 0u32);
    for &c in s {
        let (code, len) = CODES[usize::from(c)];
        acc = (acc << len) | u64::from(code);
        bits += u32::from(len);
        while bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    if bits > 0 {
        out.push(((acc << (8 - bits)) as u8) | (0xff >> bits));
    }
}

/// The static table (RFC 7541 Appendix A); index `i` is `STATIC[i - 1]`.
#[rustfmt::skip]
const STATIC: [(&[u8], &[u8]); 61] = [
    (b":authority", b""), (b":method", b"GET"), (b":method", b"POST"), (b":path", b"/"),
    (b":path", b"/index.html"), (b":scheme", b"http"), (b":scheme", b"https"),
    (b":status", b"200"), (b":status", b"204"), (b":status", b"206"), (b":status", b"304"),
    (b":status", b"400"), (b":status", b"404"), (b":status", b"500"), (b"accept-charset", b""),
    (b"accept-encoding", b"gzip, deflate"), (b"accept-language", b""), (b"accept-ranges", b""),
    (b"accept", b""), (b"access-control-allow-origin", b""), (b"age", b""), (b"allow", b""),
    (b"authorization", b""), (b"cache-control", b""), (b"content-disposition", b""),
    (b"content-encoding", b""), (b"content-language", b""), (b"content-length", b""),
    (b"content-location", b""), (b"content-range", b""), (b"content-type", b""),
    (b"cookie", b""), (b"date", b""), (b"etag", b""), (b"expect", b""), (b"expires", b""),
    (b"from", b""), (b"host", b""), (b"if-match", b""), (b"if-modified-since", b""),
    (b"if-none-match", b""), (b"if-range", b""), (b"if-unmodified-since", b""),
    (b"last-modified", b""), (b"link", b""), (b"location", b""), (b"max-forwards", b""),
    (b"proxy-authenticate", b""), (b"proxy-authorization", b""), (b"range", b""),
    (b"referer", b""), (b"refresh", b""), (b"retry-after", b""), (b"server", b""),
    (b"set-cookie", b""), (b"strict-transport-security", b""), (b"transfer-encoding", b""),
    (b"user-agent", b""), (b"vary", b""), (b"via", b""), (b"www-authenticate", b""),
];

/// The checks RFC 9113 §8.2.1 asks of every request and trailer field (akit A169), worked out
/// by the decoder as it reads a string, with one table lookup per byte, and kept with each
/// dynamic table entry: a field indexed from either table costs no byte scan at all. The HTTP/2
/// server reads them from [`Decoder::decode_classified`].
pub(crate) mod class {
    /// The name is not a regular field name: empty, a byte outside 0x21-0x40 and 0x5B-0x7E
    /// (uppercase, controls, space, 0x7F and over), or a colon. Every pseudo-header name has it.
    pub(crate) const BAD_NAME: u8 = 1;
    /// The value holds a NUL, CR or LF.
    pub(crate) const BAD_VALUE: u8 = 2;
    /// The value has a byte over 0x7F: only then does it need a UTF-8 check of its own.
    pub(crate) const NON_ASCII: u8 = 4;
    /// The name has a byte over 0x7F (it has [`BAD_NAME`] too).
    pub(crate) const NAME_NON_ASCII: u8 = 8;

    const NAME: u8 = BAD_NAME | NAME_NON_ASCII;
    const VALUE: u8 = BAD_VALUE | NON_ASCII;

    /// Every class a byte can put a field in.
    const BYTES: [u8; 256] = {
        let mut t = [0u8; 256];
        let mut i = 0;
        while i < 256 {
            let b = i as u8;
            if !matches!(b, 0x21..=0x39 | 0x3b..=0x40 | 0x5b..=0x7e) {
                t[i] |= BAD_NAME;
            }
            if matches!(b, 0 | b'\r' | b'\n') {
                t[i] |= BAD_VALUE;
            }
            if b > 0x7f {
                t[i] |= NON_ASCII | NAME_NON_ASCII;
            }
            i += 1;
        }
        t
    };

    const fn or(s: &[u8]) -> u8 {
        let (mut c, mut i) = (0, 0);
        while i < s.len() {
            c |= BYTES[s[i] as usize];
            i += 1;
        }
        c
    }

    /// The class of a name: [`BAD_NAME`], [`NAME_NON_ASCII`] or none.
    pub(crate) const fn name(n: &[u8]) -> u8 {
        if n.is_empty() {
            return BAD_NAME;
        }
        or(n) & NAME
    }

    /// The class of a value: [`BAD_VALUE`], [`NON_ASCII`] or none.
    pub(crate) const fn value(v: &[u8]) -> u8 {
        or(v) & VALUE
    }

    /// The name's part of a field's class.
    pub(crate) const fn name_part(c: u8) -> u8 {
        c & NAME
    }
}

/// The class of each static table entry ([`class`]), worked out at compile time.
const STATIC_CLASS: [u8; 61] = {
    let mut t = [0u8; 61];
    let mut i = 0;
    while i < 61 {
        t[i] = class::name(STATIC[i].0) | class::value(STATIC[i].1);
        i += 1;
    }
    t
};

/// The first static index with this name.
fn static_name(name: &[u8]) -> Option<usize> {
    Some(match name {
        b":authority" => 1,
        b":method" => 2,
        b":path" => 4,
        b":scheme" => 6,
        b":status" => 8,
        b"accept-charset" => 15,
        b"accept-encoding" => 16,
        b"accept-language" => 17,
        b"accept-ranges" => 18,
        b"accept" => 19,
        b"access-control-allow-origin" => 20,
        b"age" => 21,
        b"allow" => 22,
        b"authorization" => 23,
        b"cache-control" => 24,
        b"content-disposition" => 25,
        b"content-encoding" => 26,
        b"content-language" => 27,
        b"content-length" => 28,
        b"content-location" => 29,
        b"content-range" => 30,
        b"content-type" => 31,
        b"cookie" => 32,
        b"date" => 33,
        b"etag" => 34,
        b"expect" => 35,
        b"expires" => 36,
        b"from" => 37,
        b"host" => 38,
        b"if-match" => 39,
        b"if-modified-since" => 40,
        b"if-none-match" => 41,
        b"if-range" => 42,
        b"if-unmodified-since" => 43,
        b"last-modified" => 44,
        b"link" => 45,
        b"location" => 46,
        b"max-forwards" => 47,
        b"proxy-authenticate" => 48,
        b"proxy-authorization" => 49,
        b"range" => 50,
        b"referer" => 51,
        b"refresh" => 52,
        b"retry-after" => 53,
        b"server" => 54,
        b"set-cookie" => 55,
        b"strict-transport-security" => 56,
        b"transfer-encoding" => 57,
        b"user-agent" => 58,
        b"vary" => 59,
        b"via" => 60,
        b"www-authenticate" => 61,
        _ => return None,
    })
}

/// (first static index with the name, static index of the exact field).
fn static_find(name: &[u8], value: &[u8]) -> (Option<usize>, Option<usize>) {
    let Some(first) = static_name(name) else {
        return (None, None);
    };
    let exact = (first..=STATIC.len())
        .take_while(|&i| STATIC[i - 1].0 == name)
        .find(|&i| STATIC[i - 1].1 == value);
    (Some(first), exact)
}

/// The overhead RFC 7541 §4.1 counts per entry.
const ENTRY_OVERHEAD: usize = 32;

/// The default (and initial) dynamic table size, `SETTINGS_HEADER_TABLE_SIZE`'s default.
pub const DEFAULT_TABLE_SIZE: usize = 4096;

/// Decoded header fields, `(name, value)` in order.
pub type HeaderList = Vec<(Vec<u8>, Vec<u8>)>;

/// A dynamic table entry: name, value and, in a decoder's table, the field's [`class`] (an
/// encoder's table keeps 0 there).
type Entry = (Box<[u8]>, Box<[u8]>, u8);

/// A dynamic table: newest entry first.
#[derive(Debug)]
struct Table {
    entries: VecDeque<Entry>,
    size: usize,
    max: usize,
}

impl Table {
    fn new(max: usize) -> Table {
        Table {
            entries: VecDeque::new(),
            size: 0,
            max,
        }
    }

    fn evict_to(&mut self, max: usize) {
        while self.size > max {
            let Some((n, v, _)) = self.entries.pop_back() else {
                break;
            };
            self.size -= n.len() + v.len() + ENTRY_OVERHEAD;
        }
    }

    fn set_max(&mut self, max: usize) {
        self.max = max;
        self.evict_to(max);
    }

    /// Adds an entry, evicting old ones; an entry larger than the table empties it (§4.4).
    fn insert(&mut self, name: Box<[u8]>, value: Box<[u8]>, class: u8) {
        let size = name.len() + value.len() + ENTRY_OVERHEAD;
        if size > self.max {
            self.entries.clear();
            self.size = 0;
            return;
        }
        self.evict_to(self.max - size);
        self.size += size;
        self.entries.push_front((name, value, class));
    }

    /// The entry with HPACK index `index` (static entries first, then this table), with its
    /// [`class`].
    fn field(&self, index: usize) -> Result<(&[u8], &[u8], u8), DecoderError> {
        match index {
            0 => Err(DecoderError::InvalidIndex),
            1..=61 => Ok((
                STATIC[index - 1].0,
                STATIC[index - 1].1,
                STATIC_CLASS[index - 1],
            )),
            _ => self
                .entries
                .get(index - 62)
                .map(|(n, v, c)| (&n[..], &v[..], *c))
                .ok_or(DecoderError::InvalidIndex),
        }
    }

    /// (HPACK index of an entry with this name, of an entry with this name and value).
    fn find(&self, name: &[u8], value: &[u8]) -> (Option<usize>, Option<usize>) {
        let mut by_name = None;
        for (i, (n, v, _)) in self.entries.iter().enumerate() {
            if **n == *name {
                if **v == *value {
                    return (Some(62 + i), Some(62 + i));
                }
                by_name.get_or_insert(62 + i);
            }
        }
        (by_name, None)
    }
}

/// Why a header block does not decode. Any of these is a `COMPRESSION_ERROR` in HTTP/2.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecoderError {
    /// The block ends inside a representation.
    Truncated,
    /// An integer larger than 2^32 - 1, or with too many continuation bytes.
    IntegerOverflow,
    /// Index 0, or past the end of the dynamic table.
    InvalidIndex,
    /// A Huffman string that does not decode.
    InvalidHuffman,
    /// A dynamic table size update after the first field of a block.
    SizeUpdateNotAtStart,
    /// A dynamic table size update above the allowed maximum.
    SizeUpdateTooLarge,
}

impl fmt::Display for DecoderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            DecoderError::Truncated => "truncated header block",
            DecoderError::IntegerOverflow => "integer overflow",
            DecoderError::InvalidIndex => "invalid table index",
            DecoderError::InvalidHuffman => "invalid Huffman string",
            DecoderError::SizeUpdateNotAtStart => "table size update after a field",
            DecoderError::SizeUpdateTooLarge => "table size update above the limit",
        })
    }
}

impl std::error::Error for DecoderError {}

/// An integer with an `prefix`-bit prefix at `b[*pos]` (RFC 7541 §5.1), at most 2^32 - 1.
fn read_int(b: &[u8], pos: &mut usize, prefix: u8) -> Result<usize, DecoderError> {
    let mask = ((1u16 << prefix) - 1) as u8;
    let first = *b.get(*pos).ok_or(DecoderError::Truncated)? & mask;
    *pos += 1;
    if first < mask {
        return Ok(usize::from(first));
    }
    let mut v = u64::from(mask);
    let mut shift = 0u32;
    loop {
        let c = *b.get(*pos).ok_or(DecoderError::Truncated)?;
        *pos += 1;
        v += u64::from(c & 0x7f) << shift;
        if v > u64::from(u32::MAX) {
            return Err(DecoderError::IntegerOverflow);
        }
        if c & 0x80 == 0 {
            return usize::try_from(v).map_err(|_| DecoderError::IntegerOverflow);
        }
        shift += 7;
        if shift > 28 {
            return Err(DecoderError::IntegerOverflow);
        }
    }
}

/// Appends an integer with an `prefix`-bit prefix; `flags` fills the bits above the prefix.
fn put_int(out: &mut Vec<u8>, flags: u8, prefix: u8, mut v: usize) {
    let mask = (1usize << prefix) - 1;
    if v < mask {
        out.push(flags | v as u8);
        return;
    }
    out.push(flags | mask as u8);
    v -= mask;
    while v >= 0x80 {
        out.push((v as u8 & 0x7f) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

/// The string literal at `b[*pos]`: borrowed from `b` when raw, decoded into `scratch` when
/// Huffman-coded.
fn read_string<'a>(
    b: &'a [u8],
    pos: &mut usize,
    scratch: &'a mut Vec<u8>,
) -> Result<&'a [u8], DecoderError> {
    let huffman = *b.get(*pos).ok_or(DecoderError::Truncated)? & 0x80 != 0;
    let len = read_int(b, pos, 7)?;
    let end = pos.checked_add(len).ok_or(DecoderError::Truncated)?;
    let raw = b.get(*pos..end).ok_or(DecoderError::Truncated)?;
    *pos = end;
    if !huffman {
        return Ok(raw);
    }
    scratch.clear();
    decode_huffman(raw, scratch).map_err(|_| DecoderError::InvalidHuffman)?;
    Ok(scratch)
}

/// An HPACK decoder: one per connection direction, fed every header block in order.
#[derive(Debug)]
pub struct Decoder {
    table: Table,
    max_allowed: usize,
    name_buf: Vec<u8>,
    value_buf: Vec<u8>,
}

impl Default for Decoder {
    fn default() -> Decoder {
        Decoder::new()
    }
}

impl Decoder {
    /// A decoder with the default 4096-byte table, allowing size updates up to that.
    pub fn new() -> Decoder {
        Decoder {
            table: Table::new(DEFAULT_TABLE_SIZE),
            max_allowed: DEFAULT_TABLE_SIZE,
            name_buf: Vec::new(),
            value_buf: Vec::new(),
        }
    }

    /// The largest dynamic table size update accepted: the `SETTINGS_HEADER_TABLE_SIZE` we sent.
    pub fn set_max_allowed_table_size(&mut self, max: usize) {
        self.max_allowed = max;
    }

    /// The dynamic table's current maximum size.
    pub fn table_size_limit(&self) -> usize {
        self.table.max
    }

    /// Decodes a header block, calling `f(name, value, never_indexed)` for every field in order.
    pub fn decode_with(
        &mut self,
        block: &[u8],
        mut f: impl FnMut(&[u8], &[u8], bool),
    ) -> Result<(), DecoderError> {
        self.decode_classified(block, |n, v, never, _| f(n, v, never))
    }

    /// [`decode_with`](Self::decode_with), with each field's [`class`]: what the RFC 9113
    /// §8.2.1 checks found in it, scanned once per string read (never for an indexed field).
    pub(crate) fn decode_classified(
        &mut self,
        block: &[u8],
        mut f: impl FnMut(&[u8], &[u8], bool, u8),
    ) -> Result<(), DecoderError> {
        let mut name_buf = std::mem::take(&mut self.name_buf);
        let mut value_buf = std::mem::take(&mut self.value_buf);
        let r = self.run(block, &mut f, &mut name_buf, &mut value_buf);
        self.name_buf = name_buf;
        self.value_buf = value_buf;
        r
    }

    fn run(
        &mut self,
        b: &[u8],
        f: &mut impl FnMut(&[u8], &[u8], bool, u8),
        name_buf: &mut Vec<u8>,
        value_buf: &mut Vec<u8>,
    ) -> Result<(), DecoderError> {
        let mut pos = 0;
        let mut fields = false;
        while pos < b.len() {
            let c = b[pos];
            if c & 0x80 != 0 {
                // Indexed field (§6.1): its class came with the entry.
                let i = read_int(b, &mut pos, 7)?;
                let (n, v, cl) = self.table.field(i)?;
                f(n, v, false, cl);
                fields = true;
            } else if c & 0xe0 == 0x20 {
                // Dynamic table size update (§6.3).
                if fields {
                    return Err(DecoderError::SizeUpdateNotAtStart);
                }
                let size = read_int(b, &mut pos, 5)?;
                if size > self.max_allowed {
                    return Err(DecoderError::SizeUpdateTooLarge);
                }
                self.table.set_max(size);
            } else if c & 0x40 != 0 {
                // Literal with incremental indexing (§6.2.1).
                fields = true;
                let i = read_int(b, &mut pos, 6)?;
                let (name, name_class): (Box<[u8]>, u8) = if i == 0 {
                    let n = read_string(b, &mut pos, name_buf)?;
                    (n.into(), class::name(n))
                } else {
                    let (n, _, cl) = self.table.field(i)?;
                    (n.into(), class::name_part(cl))
                };
                let value: Box<[u8]> = read_string(b, &mut pos, value_buf)?.into();
                let cl = name_class | class::value(&value);
                f(&name, &value, false, cl);
                self.table.insert(name, value, cl);
            } else {
                // Literal without indexing (§6.2.2) or never indexed (§6.2.3).
                fields = true;
                let never = c & 0x10 != 0;
                let i = read_int(b, &mut pos, 4)?;
                if i == 0 {
                    let name = read_string(b, &mut pos, name_buf)?;
                    let value = read_string(b, &mut pos, value_buf)?;
                    f(name, value, never, class::name(name) | class::value(value));
                } else {
                    let (name, _, cl) = self.table.field(i)?;
                    let value = read_string(b, &mut pos, value_buf)?;
                    f(
                        name,
                        value,
                        never,
                        class::name_part(cl) | class::value(value),
                    );
                }
            }
        }
        Ok(())
    }

    /// Decodes a header block into its fields.
    pub fn decode(&mut self, block: &[u8]) -> Result<HeaderList, DecoderError> {
        let mut out = Vec::new();
        self.decode_with(block, |n, v, _| out.push((n.to_vec(), v.to_vec())))?;
        Ok(out)
    }

    /// Decodes a header block, keeping fields only while the header list size (RFC 9113 §6.5.2:
    /// name + value + 32 per field) stays within `max_list`; returns the fields kept and the
    /// size of the whole list. The whole block is processed either way.
    pub fn decode_limited(
        &mut self,
        block: &[u8],
        max_list: usize,
    ) -> Result<(HeaderList, usize), DecoderError> {
        let (mut out, mut size) = (Vec::new(), 0usize);
        self.decode_with(block, |n, v, _| {
            size = size.saturating_add(n.len() + v.len() + ENTRY_OVERHEAD);
            if size <= max_list {
                out.push((n.to_vec(), v.to_vec()));
            }
        })?;
        Ok((out, size))
    }
}

/// An HPACK encoder: one per connection direction.
#[derive(Debug)]
pub struct Encoder {
    table: Table,
    /// The largest table this encoder uses, whatever the peer allows.
    cap: usize,
    /// The table size the peer's decoder last learned (initially the protocol default).
    signaled: usize,
    /// The smallest table size since the last block, when it changed.
    pending: Option<usize>,
    huffman: bool,
}

impl Default for Encoder {
    fn default() -> Encoder {
        Encoder::new()
    }
}

/// Fields sent as never-indexed literals (RFC 7541 §7.1.3): credentials, and cookies short
/// enough to guess.
fn sensitive(name: &[u8], value: &[u8]) -> bool {
    match name {
        b"authorization" | b"proxy-authorization" => true,
        b"cookie" => value.len() < 20,
        _ => false,
    }
}

impl Encoder {
    /// An encoder with a 4096-byte dynamic table and Huffman coding on.
    pub fn new() -> Encoder {
        Encoder {
            table: Table::new(DEFAULT_TABLE_SIZE),
            cap: DEFAULT_TABLE_SIZE,
            signaled: DEFAULT_TABLE_SIZE,
            pending: None,
            huffman: true,
        }
    }

    /// Whether strings are Huffman-coded when that is not longer (default on).
    pub fn set_huffman(&mut self, on: bool) {
        self.huffman = on;
    }

    /// The peer's `SETTINGS_HEADER_TABLE_SIZE`: the table shrinks or grows (up to 4096 bytes)
    /// and the next block starts with the size update(s) RFC 7541 §4.2 requires.
    pub fn set_max_table_size(&mut self, peer_max: usize) {
        let size = peer_max.min(self.cap);
        if size == self.table.max && self.pending.is_none() {
            return;
        }
        self.table.set_max(size);
        self.pending = Some(self.pending.map_or(size, |m| m.min(size)));
    }

    /// Encodes `fields` (names must be lowercase for HTTP/2) into a header block.
    pub fn encode<'a>(
        &mut self,
        fields: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(fields, &mut out);
        out
    }

    /// Like [`encode`](Self::encode), appending to `out`.
    pub fn encode_into<'a>(
        &mut self,
        fields: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
        out: &mut Vec<u8>,
    ) {
        if let Some(min) = self.pending.take() {
            let size = self.table.max;
            if min < size {
                put_int(out, 0x20, 5, min);
            }
            if min < size || size != self.signaled {
                put_int(out, 0x20, 5, size);
            }
            self.signaled = size;
        }
        for (name, value) in fields {
            self.encode_field(name, value, out);
        }
    }

    fn encode_field(&mut self, name: &[u8], value: &[u8], out: &mut Vec<u8>) {
        let never = sensitive(name, value);
        let (static_name, static_exact) = static_find(name, value);
        if !never {
            if let Some(i) = static_exact {
                return put_int(out, 0x80, 7, i);
            }
        }
        let (dyn_name, dyn_exact) = self.table.find(name, value);
        if !never {
            if let Some(i) = dyn_exact {
                return put_int(out, 0x80, 7, i);
            }
        }
        let name_index = static_name.or(dyn_name);
        let size = name.len() + value.len() + ENTRY_OVERHEAD;
        // Index what fits comfortably; a field near the table size would only flush it.
        let index = !never && size <= self.table.max / 4 * 3;
        let (flags, prefix) = match (never, index) {
            (true, _) => (0x10, 4),
            (false, true) => (0x40, 6),
            (false, false) => (0x00, 4),
        };
        put_int(out, flags, prefix, name_index.unwrap_or(0));
        if name_index.is_none() {
            self.put_string(name, out);
        }
        self.put_string(value, out);
        if index {
            self.table.insert(name.into(), value.into(), 0);
        }
    }

    fn put_string(&self, s: &[u8], out: &mut Vec<u8>) {
        if self.huffman {
            let n = huffman_len(s);
            if n <= s.len() && !s.is_empty() {
                put_int(out, 0x80, 7, n);
                encode_huffman(s, out);
                return;
            }
        }
        put_int(out, 0, 7, s.len());
        out.extend_from_slice(s);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn huff(s: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        encode_huffman(s, &mut out);
        assert_eq!(out.len(), huffman_len(s));
        out
    }

    #[test]
    fn huffman_roundtrips_every_byte() {
        let all: Vec<u8> = (0..=255u8).collect();
        for s in [
            &b""[..],
            b"www.example.com",
            b"no-cache",
            b"custom-key",
            &all,
        ] {
            let mut d = Vec::new();
            decode_huffman(&huff(s), &mut d).unwrap();
            assert_eq!(d, s);
        }
        for c in 0..=255u8 {
            for len in 1..12 {
                let s = vec![c; len];
                let mut d = Vec::new();
                decode_huffman(&huff(&s), &mut d).unwrap();
                assert_eq!(d, s);
            }
        }
    }

    #[test]
    fn huffman_rfc_example_and_errors() {
        // RFC 7541 C.4.1: "www.example.com".
        let enc = [
            0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
        ];
        assert_eq!(huff(b"www.example.com"), enc);
        let mut d = Vec::new();
        decode_huffman(&enc, &mut d).unwrap();
        assert_eq!(d, b"www.example.com");
        // Padding of 8 bits (a whole 0xff byte after the string).
        let mut long = huff(b"a");
        long.push(0xff);
        assert!(decode_huffman(&long, &mut Vec::new()).is_err());
        // Padding that is not all ones: 'a' is 00011 (5 bits), pad with zeros.
        assert!(decode_huffman(&[0x18], &mut Vec::new()).is_err());
        // EOS (30 ones) inside the string.
        assert!(decode_huffman(&[0xff, 0xff, 0xff, 0xff], &mut Vec::new()).is_err());
        // Seven ones of padding are fine, alone too.
        assert!(decode_huffman(&[0xfe], &mut Vec::new()).is_err());
        assert!(decode_huffman(&[0x1f], &mut Vec::new()).is_ok());
    }

    #[test]
    fn static_lookup_matches_the_table() {
        for (i, (n, v)) in STATIC.iter().enumerate() {
            let first = STATIC.iter().position(|(m, _)| m == n).unwrap() + 1;
            assert_eq!(static_find(n, v), (Some(first), Some(i + 1)), "{i}");
        }
        assert_eq!(static_find(b":status", b"201"), (Some(8), None));
        assert_eq!(static_find(b"x-custom", b""), (None, None));
    }

    #[test]
    fn integers() {
        for (prefix, v) in [
            (5u8, 10usize),
            (5, 1337),
            (8, 42),
            (7, 127),
            (4, u32::MAX as usize),
        ] {
            let mut out = Vec::new();
            put_int(&mut out, 0, prefix, v);
            let mut pos = 0;
            assert_eq!(read_int(&out, &mut pos, prefix), Ok(v));
            assert_eq!(pos, out.len());
        }
        // RFC 7541 C.1.2: 1337 with a 5-bit prefix.
        let mut out = Vec::new();
        put_int(&mut out, 0, 5, 1337);
        assert_eq!(out, [0x1f, 0x9a, 0x0a]);
        let mut pos = 0;
        assert_eq!(
            read_int(&[0x1f, 0xff, 0xff, 0xff, 0xff, 0x0f], &mut pos, 5),
            Err(DecoderError::IntegerOverflow)
        );
        let mut pos = 0;
        assert_eq!(
            read_int(&[0x1f, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01], &mut pos, 5),
            Err(DecoderError::IntegerOverflow)
        );
        let mut pos = 0;
        assert_eq!(
            read_int(&[0x1f, 0x80], &mut pos, 5),
            Err(DecoderError::Truncated)
        );
    }

    type Fields = Vec<(Vec<u8>, Vec<u8>)>;

    fn fields(list: &[(&str, &str)]) -> Fields {
        list.iter()
            .map(|(n, v)| (n.as_bytes().to_vec(), v.as_bytes().to_vec()))
            .collect()
    }

    fn table(d: &Table) -> Vec<(String, String)> {
        d.entries
            .iter()
            .map(|(n, v, _)| {
                (
                    String::from_utf8_lossy(n).into_owned(),
                    String::from_utf8_lossy(v).into_owned(),
                )
            })
            .collect()
    }

    /// RFC 7541 Appendix C.2: single literal representations.
    #[test]
    fn rfc_c2_literals() {
        let mut d = Decoder::new();
        let c21 = b"\x40\x0acustom-key\x0dcustom-header";
        assert_eq!(
            d.decode(c21).unwrap(),
            fields(&[("custom-key", "custom-header")])
        );
        assert_eq!(d.table.size, 55);
        let mut d = Decoder::new();
        let c22 = b"\x04\x0c/sample/path";
        assert_eq!(d.decode(c22).unwrap(), fields(&[(":path", "/sample/path")]));
        assert_eq!(d.table.size, 0);
        let c23 = b"\x10\x08password\x06secret";
        let mut never = false;
        d.decode_with(c23, |n, v, ni| {
            assert_eq!((n, v), (&b"password"[..], &b"secret"[..]));
            never = ni;
        })
        .unwrap();
        assert!(never);
        assert_eq!(d.table.size, 0);
        assert_eq!(d.decode(b"\x82").unwrap(), fields(&[(":method", "GET")]));
        // The encoder side: a never-indexed credential.
        let mut e = Encoder::new();
        e.set_huffman(false);
        assert_eq!(
            e.encode([(&b"authorization"[..], &b"secret"[..])]),
            b"\x1f\x08\x06secret"
        );
        assert!(e.table.entries.is_empty());
    }

    /// RFC 7541 Appendix C.3 (requests without Huffman) and C.4 (with): decode and encode.
    #[test]
    fn rfc_c3_c4_requests() {
        let reqs: [&[(&str, &str)]; 3] = [
            &[
                (":method", "GET"),
                (":scheme", "http"),
                (":path", "/"),
                (":authority", "www.example.com"),
            ],
            &[
                (":method", "GET"),
                (":scheme", "http"),
                (":path", "/"),
                (":authority", "www.example.com"),
                ("cache-control", "no-cache"),
            ],
            &[
                (":method", "GET"),
                (":scheme", "https"),
                (":path", "/index.html"),
                (":authority", "www.example.com"),
                ("custom-key", "custom-value"),
            ],
        ];
        let raw: [&[u8]; 3] = [
            b"\x82\x86\x84\x41\x0fwww.example.com",
            b"\x82\x86\x84\xbe\x58\x08no-cache",
            b"\x82\x87\x85\xbf\x40\x0acustom-key\x0ccustom-value",
        ];
        let huffman: [&[u8]; 3] = [
            &[
                0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab,
                0x90, 0xf4, 0xff,
            ],
            &[
                0x82, 0x86, 0x84, 0xbe, 0x58, 0x86, 0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf,
            ],
            &[
                0x82, 0x87, 0x85, 0xbf, 0x40, 0x88, 0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f,
                0x89, 0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf,
            ],
        ];
        let sizes = [57, 110, 164];
        for (blocks, h) in [(raw, false), (huffman, true)] {
            let (mut d, mut e) = (Decoder::new(), Encoder::new());
            e.set_huffman(h);
            for (k, blk) in blocks.iter().enumerate() {
                assert_eq!(
                    d.decode(blk).unwrap(),
                    fields(reqs[k]),
                    "C.{} #{k}",
                    3 + u8::from(h)
                );
                assert_eq!(d.table.size, sizes[k]);
                let enc = e.encode(reqs[k].iter().map(|(n, v)| (n.as_bytes(), v.as_bytes())));
                assert_eq!(enc, *blk, "encoding C.{} #{k}", 3 + u8::from(h));
            }
            assert_eq!(
                table(&d.table),
                [
                    ("custom-key".into(), "custom-value".into()),
                    ("cache-control".into(), "no-cache".into()),
                    (":authority".into(), "www.example.com".into())
                ]
            );
        }
    }

    /// RFC 7541 Appendix C.5 (responses without Huffman) and C.6 (with), with a 256-byte
    /// table: eviction.
    #[test]
    fn rfc_c5_c6_responses() {
        let date1 = "Mon, 21 Oct 2013 20:13:21 GMT";
        let date2 = "Mon, 21 Oct 2013 20:13:22 GMT";
        let loc = "https://www.example.com";
        let cookie = "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1";
        let resps: [&[(&str, &str)]; 3] = [
            &[
                (":status", "302"),
                ("cache-control", "private"),
                ("date", date1),
                ("location", loc),
            ],
            &[
                (":status", "307"),
                ("cache-control", "private"),
                ("date", date1),
                ("location", loc),
            ],
            &[
                (":status", "200"),
                ("cache-control", "private"),
                ("date", date2),
                ("location", loc),
                ("content-encoding", "gzip"),
                ("set-cookie", cookie),
            ],
        ];
        let mut raw1 = b"\x48\x03302\x58\x07private\x61\x1d".to_vec();
        raw1.extend_from_slice(date1.as_bytes());
        raw1.extend_from_slice(b"\x6e\x17");
        raw1.extend_from_slice(loc.as_bytes());
        let mut raw3 = b"\x88\xc1\x61\x1d".to_vec();
        raw3.extend_from_slice(date2.as_bytes());
        raw3.extend_from_slice(b"\xc0\x5a\x04gzip\x77\x38");
        raw3.extend_from_slice(cookie.as_bytes());
        let raw: [&[u8]; 3] = [&raw1, b"\x48\x03307\xc1\xc0\xbf", &raw3];
        let huffman: [&[u8]; 3] = [
            &[
                0x48, 0x82, 0x64, 0x02, 0x58, 0x85, 0xae, 0xc3, 0x77, 0x1a, 0x4b, 0x61, 0x96, 0xd0,
                0x7a, 0xbe, 0x94, 0x10, 0x54, 0xd4, 0x44, 0xa8, 0x20, 0x05, 0x95, 0x04, 0x0b, 0x81,
                0x66, 0xe0, 0x82, 0xa6, 0x2d, 0x1b, 0xff, 0x6e, 0x91, 0x9d, 0x29, 0xad, 0x17, 0x18,
                0x63, 0xc7, 0x8f, 0x0b, 0x97, 0xc8, 0xe9, 0xae, 0x82, 0xae, 0x43, 0xd3,
            ],
            &[0x48, 0x83, 0x64, 0x0e, 0xff, 0xc1, 0xc0, 0xbf],
            &[
                0x88, 0xc1, 0x61, 0x96, 0xd0, 0x7a, 0xbe, 0x94, 0x10, 0x54, 0xd4, 0x44, 0xa8, 0x20,
                0x05, 0x95, 0x04, 0x0b, 0x81, 0x66, 0xe0, 0x84, 0xa6, 0x2d, 0x1b, 0xff, 0xc0, 0x5a,
                0x83, 0x9b, 0xd9, 0xab, 0x77, 0xad, 0x94, 0xe7, 0x82, 0x1d, 0xd7, 0xf2, 0xe6, 0xc7,
                0xb3, 0x35, 0xdf, 0xdf, 0xcd, 0x5b, 0x39, 0x60, 0xd5, 0xaf, 0x27, 0x08, 0x7f, 0x36,
                0x72, 0xc1, 0xab, 0x27, 0x0f, 0xb5, 0x29, 0x1f, 0x95, 0x87, 0x31, 0x60, 0x65, 0xc0,
                0x03, 0xed, 0x4e, 0xe5, 0xb1, 0x06, 0x3d, 0x50, 0x07,
            ],
        ];
        let sizes = [222, 222, 215];
        for (blocks, h) in [(raw, false), (huffman, true)] {
            let (mut d, mut e) = (Decoder::new(), Encoder::new());
            // The examples run with a 256-byte table from the start (no size update sent).
            d.table.set_max(256);
            e.table.set_max(256);
            e.signaled = 256;
            e.set_huffman(h);
            for (k, blk) in blocks.iter().enumerate() {
                assert_eq!(
                    d.decode(blk).unwrap(),
                    fields(resps[k]),
                    "C.{} #{k}",
                    5 + u8::from(h)
                );
                assert_eq!(d.table.size, sizes[k]);
                let enc = e.encode(resps[k].iter().map(|(n, v)| (n.as_bytes(), v.as_bytes())));
                assert_eq!(enc, *blk, "encoding C.{} #{k}", 5 + u8::from(h));
            }
            assert_eq!(
                table(&d.table),
                [
                    ("set-cookie".into(), cookie.into()),
                    ("content-encoding".into(), "gzip".into()),
                    ("date".into(), date2.into())
                ]
            );
        }
    }

    #[test]
    fn decoder_errors() {
        let mut d = Decoder::new();
        assert_eq!(d.decode(b"\x80"), Err(DecoderError::InvalidIndex));
        assert_eq!(d.decode(b"\xbe"), Err(DecoderError::InvalidIndex));
        assert_eq!(d.decode(b"\x7e\x01a"), Err(DecoderError::InvalidIndex));
        assert_eq!(d.decode(b"\x41\x8c\xf1"), Err(DecoderError::Truncated));
        assert_eq!(d.decode(b"\x40\x01a"), Err(DecoderError::Truncated));
        assert_eq!(d.decode(b"\x41\x81\x00"), Err(DecoderError::InvalidHuffman));
        // Size updates: at the start only, never above the allowed maximum.
        assert_eq!(
            d.decode(b"\x82\x20"),
            Err(DecoderError::SizeUpdateNotAtStart)
        );
        assert_eq!(
            d.decode(b"\x3f\xe2\x1f"),
            Err(DecoderError::SizeUpdateTooLarge)
        );
        assert!(d.decode(b"\x20\x3f\xe1\x1f\x82").is_ok());
        d.set_max_allowed_table_size(100);
        assert_eq!(d.decode(b"\x3f\x46"), Err(DecoderError::SizeUpdateTooLarge));
        assert!(d.decode(b"\x3f\x45").is_ok());
        assert_eq!(d.table_size_limit(), 100);
    }

    #[test]
    fn size_updates_and_eviction() {
        let (mut d, mut e) = (Decoder::new(), Encoder::new());
        let a = vec![b'a'; 3000];
        let blk = e.encode([(&b"x-big"[..], &a[..]), (b"x-small", b"1")]);
        let mut d2 = Decoder::new();
        assert_eq!(d.decode(&blk).unwrap(), d2.decode(&blk).unwrap());
        // Shrink to 0 and back to 100: both updates are signaled, in order.
        e.set_max_table_size(0);
        e.set_max_table_size(100);
        let blk = e.encode([(&b"x-small"[..], &b"1"[..])]);
        assert_eq!(&blk[..3], b"\x20\x3f\x45");
        let list = d.decode(&blk).unwrap();
        assert_eq!(list, fields(&[("x-small", "1")]));
        assert_eq!(d.table_size_limit(), 100);
        assert_eq!(table(&d.table), table(&e.table));
        // No change, no update; growing past the cap stays at 4096.
        e.set_max_table_size(100);
        assert_eq!(e.encode([(&b"x-small"[..], &b"1"[..])]), b"\xbe");
        e.set_max_table_size(1 << 20);
        let blk = e.encode([]);
        assert_eq!(blk, b"\x3f\xe1\x1f");
        // A field larger than the table empties it.
        let mut t = Table::new(64);
        t.insert(b"a"[..].into(), b"b"[..].into(), 0);
        t.insert(vec![b'n'; 40].into(), b""[..].into(), 0);
        assert!(t.entries.is_empty());
        assert_eq!(t.size, 0);
    }

    #[test]
    fn limited_decoding_keeps_the_table_in_step() {
        let mut e = Encoder::new();
        let v = vec![b'v'; 1000];
        let blk = e.encode([(&b"x-a"[..], &v[..]), (b"x-b", &v[..]), (b"x-c", b"c")]);
        let mut d = Decoder::new();
        let (list, size) = d.decode_limited(&blk, 1100).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(size, 3 * 32 + 9 + 2001);
        assert_eq!(table(&d.table), table(&e.table));
    }

    /// The checks as A169 wrote them, one predicate per byte: the classes must agree.
    fn reference(n: &[u8], v: &[u8]) -> u8 {
        let mut c = 0;
        if n.is_empty()
            || !n
                .iter()
                .all(|&b| matches!(b, 0x21..=0x40 | 0x5b..=0x7e) && b != b':')
        {
            c |= class::BAD_NAME;
        }
        if n.iter().any(|&b| b > 0x7f) {
            c |= class::NAME_NON_ASCII;
        }
        if v.iter().any(|&b| matches!(b, 0 | b'\r' | b'\n')) {
            c |= class::BAD_VALUE;
        }
        if v.iter().any(|&b| b > 0x7f) {
            c |= class::NON_ASCII;
        }
        c
    }

    #[test]
    fn field_classes_match_the_rfc_9113_checks() {
        for b in 0..=255u8 {
            for s in [vec![b], vec![b'x', b], vec![b, b'-', b'y']] {
                let got = class::name(&s) | class::value(&s);
                assert_eq!(got, reference(&s, &s), "{s:?}");
            }
        }
        assert_eq!(class::name(b""), class::BAD_NAME);
        assert_eq!(class::value(b""), 0);
        for (i, (n, v)) in STATIC.iter().enumerate() {
            assert_eq!(STATIC_CLASS[i], reference(n, v), "static {}", i + 1);
        }
    }

    /// Every representation hands the decoder's callback the class of what it decoded: the
    /// literal forms scan their strings, an indexed field (static or dynamic) brings the class
    /// worked out when its entry was made, a literal with an indexed name takes that name's.
    #[test]
    fn decoded_fields_carry_their_class() {
        let fields: &[(&[u8], &[u8])] = &[
            (b":method", b"GET"),
            (b":path", b"/a\nb"),
            (b"x-ok", b"plain"),
            (b"X-Up", b"1"),
            (b"x a", b"1"),
            (b"x\xc3\xa9", b"1"),
            (b"x-cr", b"a\rb"),
            (b"x-nul", b"a\0b"),
            (b"x-utf8", b"caf\xc3\xa9"),
            (b"", b"empty name"),
            (b"cookie", b"secret"),
            (b"user-agent", b"x\ny"),
        ];
        for huffman in [true, false] {
            let mut e = Encoder::new();
            e.set_huffman(huffman);
            let mut d = Decoder::new();
            // Twice: literals first, then mostly indexed from the dynamic table.
            for _ in 0..2 {
                let blk = e.encode(fields.iter().copied());
                let mut got = Vec::new();
                d.decode_classified(&blk, |n, v, _, c| got.push((n.to_vec(), v.to_vec(), c)))
                    .unwrap();
                assert_eq!(got.len(), fields.len());
                for ((n, v, c), (n0, v0)) in got.iter().zip(fields) {
                    assert_eq!((&n[..], &v[..]), (*n0, *v0));
                    assert_eq!(*c, reference(n, v), "{n0:?}: {v0:?}");
                }
            }
        }
        // A literal whose name is indexed: `user-agent` (static 58) with a value, `x-up`'s
        // dynamic entry with another one.
        let mut d = Decoder::new();
        let mut blk = vec![0x0f, 0x2b, 3];
        blk.extend_from_slice(b"a\rb");
        blk.extend_from_slice(&[0x40, 3]);
        blk.extend_from_slice(b"X-U");
        blk.extend_from_slice(&[1, b'1', 0x0f, 0x2f, 2]);
        blk.extend_from_slice(b"\xc3\xa9");
        let mut got = Vec::new();
        d.decode_classified(&blk, |n, v, _, c| got.push((n.to_vec(), v.to_vec(), c)))
            .unwrap();
        assert_eq!(got.len(), 3);
        for (n, v, c) in &got {
            assert_eq!(*c, reference(n, v), "{n:?}: {v:?}");
        }
        assert_eq!(got[2].0, b"X-U");
        assert_eq!(got[2].2, class::BAD_NAME | class::NON_ASCII);
    }
}
