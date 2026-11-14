//! HPACK helpers: a Huffman decoder whose table is built once (RFC 7541 §5.2, Appendix B).
//!
//! `loona-hpack` rebuilds its Huffman decoding table (nested hash maps of 257 codes) for every
//! Huffman-coded string, which made header decoding the dominant cost of an HTTP/2 request.
//! [`strip_huffman`] rewrites a header block so that every string literal is raw, decoding the
//! Huffman ones here; the block then goes to `loona-hpack` unchanged otherwise, so its dynamic
//! table and validation stay in charge.

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

/// Binary decoding tree: node `i` has children `TREE[i][bit]`; a value `>= LEAF` is the leaf of
/// symbol `value - LEAF`, 0 is "no child" (the root is never a child).
const LEAF: u16 = 0x8000;

fn tree() -> &'static [[u16; 2]] {
    static TREE: OnceLock<Vec<[u16; 2]>> = OnceLock::new();
    TREE.get_or_init(|| {
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
    })
}

/// A Huffman-coded string that does not decode (see [`decode_huffman`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidHuffman;

/// Decodes a Huffman-coded string, appending to `out`. Fails on the EOS symbol, on padding longer
/// than 7 bits, and on padding that is not all ones (RFC 7541 §5.2).
pub fn decode_huffman(src: &[u8], out: &mut Vec<u8>) -> Result<(), InvalidHuffman> {
    let t = tree();
    let mut node = 0usize;
    // Bits read since the last symbol, and whether they were all ones (valid padding).
    let (mut pending, mut ones) = (0u32, true);
    for &byte in src {
        for i in (0..8).rev() {
            let bit = (byte >> i) & 1;
            let next = t[node][bit as usize];
            if next >= LEAF {
                let sym = next & !LEAF;
                if sym == EOS {
                    return Err(InvalidHuffman);
                }
                out.push(sym as u8);
                (node, pending, ones) = (0, 0, true);
            } else if next == 0 {
                return Err(InvalidHuffman); // cannot happen with a complete code, kept for safety
            } else {
                node = next as usize;
                pending += 1;
                ones &= bit == 1;
            }
        }
    }
    if pending > 7 || !ones {
        return Err(InvalidHuffman);
    }
    Ok(())
}

/// An HPACK integer with an `n`-bit prefix at `b[*pos]`: (value, bytes). At most 5 bytes, as
/// `loona-hpack` accepts.
fn int(b: &[u8], pos: usize, n: u8) -> Result<(usize, usize), ()> {
    let mask = ((1u16 << n) - 1) as u8;
    let first = *b.get(pos).ok_or(())? & mask;
    if first < mask {
        return Ok((first as usize, 1));
    }
    let (mut v, mut m) = (first as usize, 0u32);
    for k in 1..5 {
        let c = *b.get(pos + k).ok_or(())?;
        v += ((c & 0x7f) as usize) << m;
        m += 7;
        if c & 0x80 == 0 {
            return Ok((v, k + 1));
        }
    }
    Err(())
}

fn put_int(out: &mut Vec<u8>, flags: u8, n: u8, mut v: usize) {
    let mask = (1usize << n) - 1;
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

/// Copies the string literal at `b[*pos]` to `out` as a raw (non-Huffman) literal.
fn string(b: &[u8], pos: &mut usize, out: &mut Vec<u8>) -> Result<(), ()> {
    let huff = *b.get(*pos).ok_or(())? & 0x80 != 0;
    let (len, n) = int(b, *pos, 7)?;
    let start = *pos + n;
    let raw = b.get(start..start.checked_add(len).ok_or(())?).ok_or(())?;
    if huff {
        let mut s = Vec::with_capacity(len + len / 2);
        decode_huffman(raw, &mut s).map_err(drop)?;
        put_int(out, 0, 7, s.len());
        out.extend_from_slice(&s);
    } else {
        out.extend_from_slice(&b[*pos..start + len]);
    }
    *pos = start + len;
    Ok(())
}

/// Rewrites a header block with every Huffman-coded string literal replaced by its raw form;
/// everything else is copied unchanged. Fails on a block that is malformed at this level
/// (truncated, bad Huffman); the decoder would reject those too.
pub(crate) fn strip_huffman(b: &[u8]) -> Result<Vec<u8>, ()> {
    let mut out = Vec::with_capacity(b.len() + b.len() / 2);
    let mut pos = 0;
    while pos < b.len() {
        let c = b[pos];
        let (prefix, literal) = match c {
            _ if c & 0x80 != 0 => (7, false),    // indexed field
            _ if c & 0xc0 == 0x40 => (6, true),  // literal with incremental indexing
            _ if c & 0xe0 == 0x20 => (5, false), // dynamic table size update
            _ => (4, true),                      // literal without indexing / never indexed
        };
        let (index, n) = int(b, pos, prefix)?;
        out.extend_from_slice(&b[pos..pos + n]);
        pos += n;
        if literal {
            if index == 0 {
                string(b, &mut pos, &mut out)?;
            }
            string(b, &mut pos, &mut out)?;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode(s: &[u8]) -> Vec<u8> {
        let (mut acc, mut bits, mut out) = (0u64, 0u32, Vec::new());
        for &c in s {
            let (code, len) = CODES[c as usize];
            acc = (acc << len) | code as u64;
            bits += len as u32;
            while bits >= 8 {
                out.push((acc >> (bits - 8)) as u8);
                bits -= 8;
            }
        }
        if bits > 0 {
            out.push(((acc << (8 - bits)) as u8) | (0xff >> bits));
        }
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
            decode_huffman(&encode(s), &mut d).unwrap();
            assert_eq!(d, s);
        }
    }

    #[test]
    fn huffman_rfc_example_and_errors() {
        // RFC 7541 C.4.1: "www.example.com".
        let enc = [
            0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
        ];
        let mut d = Vec::new();
        decode_huffman(&enc, &mut d).unwrap();
        assert_eq!(d, b"www.example.com");
        // Padding of 8 bits (a whole 0xff byte after the string).
        let mut long = encode(b"a");
        long.push(0xff);
        assert!(decode_huffman(&long, &mut Vec::new()).is_err());
        // Padding that is not all ones: 'a' is 00011 (5 bits), pad with zeros.
        assert!(decode_huffman(&[0x18], &mut Vec::new()).is_err());
        // EOS (30 ones) inside the string.
        assert!(decode_huffman(&[0xff, 0xff, 0xff, 0xff], &mut Vec::new()).is_err());
    }

    #[test]
    fn strip_matches_loona_on_rfc_requests() {
        // RFC 7541 C.4.1-C.4.3: three requests with Huffman coding, sharing a dynamic table.
        let blocks: [&[u8]; 3] = [
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
        let (mut a, mut b) = (loona_hpack::Decoder::new(), loona_hpack::Decoder::new());
        for blk in blocks {
            let direct = a.decode(blk).unwrap();
            let stripped = strip_huffman(blk).unwrap();
            assert!(stripped.len() > blk.len());
            assert_eq!(b.decode(&stripped).unwrap(), direct);
        }
        assert!(strip_huffman(&[0x41, 0x8c, 0xf1]).is_err()); // truncated
    }
}
